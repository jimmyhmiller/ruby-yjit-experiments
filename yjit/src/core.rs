use crate::{
    asm::{CodeBlock, OutlinedCb},
    backend::ir::{Assembler, Opnd, C_ARG_OPNDS, EC},
    bbv::{add_block_version, find_block_version, remove_block_version},
    codegen::{gen_entry_prologue, gen_single_block, globals::CodegenGlobals, CodeGenerator},
    cruby::{
        get_cfp_pc, get_cfp_sp, get_ec_cfp, get_iseq_encoded_size, imemo_iseq, rb_IMEMO_TYPE_P,
        rb_cfp_get_iseq, rb_iseq_pc_at_idx, rb_iseq_reset_jit_func, rb_set_cfp_pc, rb_set_cfp_sp,
        src_loc, with_vm_lock, EcPtr, IseqPtr,
    },
    dev::options::get_option,
    dev::stats::incr_counter,
    iseq::get_iseq_payload,
    meta::block::{
        BlockId, BlockRef, Branch, BranchGenFn, BranchRef, BranchShape, BranchStub, BranchTarget,
    },
    meta::context::Context,
    meta::invariants::block_assumptions_free,
    meta::jit_state::JITState,
    utils::{c_callable, IntoUsize},
    virtualmem::CodePtr,
};

use core::ffi::c_void;
use std::cell::{RefCell, RefMut};
use std::mem;
use std::rc::Rc;

#[cfg(feature = "disasm")]
use crate::dev::disasm::disasm_iseq_insn_range;

/// See [gen_block_series_body]. This simply counts compilation failures.
fn gen_block_series(
    blockid: BlockId,
    start_ctx: &Context,
    ec: EcPtr,
    cb: &mut CodeBlock,
) -> Option<BlockRef> {
    let result = gen_block_series_body(blockid, start_ctx, ec, cb);
    if result.is_none() {
        incr_counter!(compilation_failure);
    }

    result
}

/// Immediately compile a series of block versions at a starting point and
/// return the starting block.
pub fn gen_block_series_body(
    blockid: BlockId,
    start_ctx: &Context,
    ec: EcPtr,
    cb: &mut CodeBlock,
) -> Option<BlockRef> {
    // Keep track of all blocks compiled in this batch
    const EXPECTED_BATCH_SIZE: usize = 4;
    let mut batch = Vec::with_capacity(EXPECTED_BATCH_SIZE);

    // Generate code for the first block
    let first_block = gen_single_block(blockid, start_ctx, ec, cb).ok()?;
    batch.push(first_block.clone()); // Keep track of this block version

    // Add the block version to the VersionMap for this ISEQ
    add_block_version(&first_block, cb);

    // Loop variable
    let mut last_blockref = first_block.clone();
    loop {
        // Get the last outgoing branch from the previous block.
        let last_branchref = {
            let last_block = last_blockref.borrow();
            match last_block.outgoing.last() {
                Some(branch) => branch.clone(),
                None => {
                    break;
                } // If last block has no branches, stop.
            }
        };
        let mut last_branch = last_branchref.borrow_mut();

        // gen_direct_jump() can request a block to be placed immediately after by
        // leaving a single target that has a `None` address.
        let last_target = match &mut last_branch.targets {
            [Some(last_target), None] if last_target.get_address().is_none() => last_target,
            _ => break,
        };

        incr_counter!(block_next_count);

        // Get id and context for the new block
        let requested_blockid = last_target.get_blockid();
        let requested_ctx = last_target.get_ctx();

        // Generate new block using context from the last branch.
        let result = gen_single_block(requested_blockid, &requested_ctx, ec, cb);

        // If the block failed to compile
        if result.is_err() {
            // Remove previously compiled block
            // versions from the version map
            mem::drop(last_branch); // end borrow
            for blockref in &batch {
                free_block(blockref);
                remove_block_version(blockref);
            }

            // Stop compiling
            return None;
        }

        let new_blockref = result.unwrap();

        // Add the block version to the VersionMap for this ISEQ
        add_block_version(&new_blockref, cb);

        // Connect the last branch and the new block
        last_branch.targets[0] = Some(Box::new(BranchTarget::Block(new_blockref.clone())));
        new_blockref
            .borrow_mut()
            .push_incoming(last_branchref.clone());

        // Track the block
        batch.push(new_blockref.clone());

        // Repeat with newest block
        last_blockref = new_blockref;
    }

    #[cfg(feature = "disasm")]
    {
        use crate::dev::options::get_option_ref;
        use crate::utils::iseq_get_location;
        // If dump_iseq_disasm is active, see if this iseq's location matches the given substring.
        // If so, we print the new blocks to the console.
        if let Some(substr) = get_option_ref!(dump_iseq_disasm).as_ref() {
            let blockid_idx = blockid.idx;
            let iseq_location = iseq_get_location(blockid.iseq, blockid_idx);
            if iseq_location.contains(substr) {
                let last_block = last_blockref.borrow();
                println!(
                    "Compiling {} block(s) for {}, ISEQ offsets [{}, {})",
                    batch.len(),
                    iseq_location,
                    blockid_idx,
                    last_block.end_idx
                );
                print!(
                    "{}",
                    disasm_iseq_insn_range(blockid.iseq, blockid.idx, last_block.end_idx)
                );
            }
        }
    }

    Some(first_block)
}

/// Generate a block version that is an entry point inserted into an iseq
/// NOTE: this function assumes that the VM lock has been taken
pub fn gen_entry_point(iseq: IseqPtr, ec: EcPtr) -> Option<CodePtr> {
    // Compute the current instruction index based on the current PC
    let insn_idx: u32 = unsafe {
        let pc_zero = rb_iseq_pc_at_idx(iseq, 0);
        let ec_pc = get_cfp_pc(get_ec_cfp(ec));
        ec_pc.offset_from(pc_zero).try_into().ok()?
    };

    // The entry context makes no assumptions about types
    let blockid = BlockId {
        iseq,
        idx: insn_idx,
    };

    // Get the inline and outlined code blocks
    let cb = CodegenGlobals::get_inline_cb();

    // Write the interpreter entry prologue. Might be NULL when out of memory.
    let code_ptr = gen_entry_prologue(cb, iseq, insn_idx);

    // Try to generate code for the entry block
    let block = gen_block_series(blockid, &Context::default(), ec, cb);

    cb.mark_all_executable();
    CodegenGlobals::with_outlined_cb(|ocb| ocb.unwrap().mark_all_executable());
    match block {
        // Compilation failed
        None => {
            // Trigger code GC. This entry point will be recompiled later.
            cb.code_gc();
            return None;
        }

        // If the block contains no Ruby instructions
        Some(block) => {
            let block = block.borrow();
            if block.end_idx == insn_idx {
                return None;
            }
        }
    }

    // Compilation successful and block not empty
    code_ptr
}

/// Generate code for a branch, possibly rewriting and changing the size of it
fn regenerate_branch(cb: &mut CodeBlock, branch: &mut Branch) {
    // Remove old comments
    if let (Some(start_addr), Some(end_addr)) = (branch.start_addr, branch.end_addr) {
        cb.remove_comments(start_addr, end_addr)
    }

    let branch_terminates_block = branch.end_addr == branch.block.borrow().end_addr;

    // Generate the branch
    let mut asm = Assembler::new();
    asm.comment("regenerate_branch");
    branch.gen_fn.call(
        &mut asm,
        branch.get_target_address(0).unwrap(),
        branch.get_target_address(1),
    );

    // Rewrite the branch
    let old_write_pos = cb.get_write_pos();
    let old_dropped_bytes = cb.has_dropped_bytes();
    cb.set_write_ptr(branch.start_addr.unwrap());
    cb.set_dropped_bytes(false);
    asm.compile(cb);

    branch.end_addr = Some(cb.get_write_ptr());

    // The block may have shrunk after the branch is rewritten
    let mut block = branch.block.borrow_mut();
    if branch_terminates_block {
        // Adjust block size
        block.end_addr = branch.end_addr;
    }

    // cb.write_pos is both a write cursor and a marker for the end of
    // everything written out so far. Leave cb->write_pos at the end of the
    // block before returning. This function only ever bump or retain the end
    // of block marker since that's what the majority of callers want. When the
    // branch sits at the very end of the codeblock and it shrinks after
    // regeneration, it's up to the caller to drop bytes off the end to
    // not leave a gap and implement branch->shape.
    if old_write_pos > cb.get_write_pos() {
        // We rewound cb->write_pos to generate the branch, now restore it.
        cb.set_pos(old_write_pos);
        cb.set_dropped_bytes(old_dropped_bytes);
    } else {
        // The branch sits at the end of cb and consumed some memory.
        // Keep cb.write_pos.
    }
}

/// Create a new outgoing branch entry for a block
pub fn make_branch_entry(jit: &mut JITState, block: &BlockRef, gen_fn: BranchGenFn) -> BranchRef {
    let branch = Branch {
        // Block this is attached to
        block: block.clone(),

        // Positions where the generated code starts and ends
        start_addr: None,
        end_addr: None,

        // Branch target blocks and their contexts
        targets: [None, None],

        // Branch code generation function
        gen_fn,
    };

    // Add to the list of outgoing branches for the block
    let branchref = Rc::new(RefCell::new(branch));
    jit.push_outgoing(branchref.clone());
    incr_counter!(compiled_branch_count);

    branchref
}

c_callable! {
    /// Generated code calls this function with the SysV calling convention.
    /// See [set_branch_target].
    fn branch_stub_hit(
        branch_ptr: *const c_void,
        target_idx: u32,
        ec: EcPtr,
    ) -> *const u8 {
        with_vm_lock(src_loc!(), || {
            branch_stub_hit_body(branch_ptr, target_idx, ec)
        })
    }
}

/// Called by the generated code when a branch stub is executed
/// Triggers compilation of branches and code patching
fn branch_stub_hit_body(branch_ptr: *const c_void, target_idx: u32, ec: EcPtr) -> *const u8 {
    if get_option!(dump_insns) {
        println!("branch_stub_hit");
    }

    assert!(!branch_ptr.is_null());

    //branch_ptr is actually:
    //branch_ptr: *const RefCell<Branch>
    let branch_rc = unsafe { BranchRef::from_raw(branch_ptr as *const RefCell<Branch>) };

    // We increment the strong count because we want to keep the reference owned
    // by the branch stub alive. Return branch stubs can be hit multiple times.
    unsafe { Rc::increment_strong_count(branch_ptr) };

    let mut branch = branch_rc.borrow_mut();
    let branch_size_on_entry = branch.code_size();

    let target_idx: usize = target_idx.into_usize();
    let target = branch.targets[target_idx].as_ref().unwrap();
    let target_blockid = target.get_blockid();
    let target_ctx = target.get_ctx();

    let target_branch_shape = match target_idx {
        0 => BranchShape::Next0,
        1 => BranchShape::Next1,
        _ => unreachable!("target_idx < 2 must always hold"),
    };

    let cb = CodegenGlobals::get_inline_cb();

    // If this branch has already been patched, return the dst address
    // Note: ractors can cause the same stub to be hit multiple times
    if let BranchTarget::Block(_) = target.as_ref() {
        return target.get_address().unwrap().raw_ptr();
    }

    let (cfp, original_interp_sp) = unsafe {
        let cfp = get_ec_cfp(ec);
        let original_interp_sp = get_cfp_sp(cfp);

        let running_iseq = rb_cfp_get_iseq(cfp);
        let reconned_pc = rb_iseq_pc_at_idx(running_iseq, target_blockid.idx);
        let reconned_sp = original_interp_sp.offset(target_ctx.sp_offset.into());

        assert_eq!(
            running_iseq, target_blockid.iseq as _,
            "each stub expects a particular iseq"
        );

        // Update the PC in the current CFP, because it may be out of sync in JITted code
        rb_set_cfp_pc(cfp, reconned_pc);

        // :stub-sp-flush:
        // Generated code do stack operations without modifying cfp->sp, while the
        // cfp->sp tells the GC what values on the stack to root. Generated code
        // generally takes care of updating cfp->sp when it calls runtime routines that
        // could trigger GC, but it's inconvenient to do it before calling this function.
        // So we do it here instead.
        rb_set_cfp_sp(cfp, reconned_sp);

        (cfp, original_interp_sp)
    };

    // Try to find an existing compiled version of this block
    let mut block = find_block_version(target_blockid, &target_ctx);

    // If this block hasn't yet been compiled
    if block.is_none() {
        let branch_old_shape = branch.gen_fn.get_shape();
        let mut branch_modified = false;

        // If the new block can be generated right after the branch (at cb->write_pos)
        if Some(cb.get_write_ptr()) == branch.end_addr {
            // This branch should be terminating its block
            assert!(branch.end_addr == branch.block.borrow().end_addr);

            // Change the branch shape to indicate the target block will be placed next
            branch.gen_fn.set_shape(target_branch_shape);

            // Rewrite the branch with the new, potentially more compact shape
            regenerate_branch(cb, &mut branch);
            branch_modified = true;

            // Ensure that the branch terminates the codeblock just like
            // before entering this if block. This drops bytes off the end
            // in case we shrank the branch when regenerating.
            cb.set_write_ptr(branch.end_addr.unwrap());
        }

        // Compile the new block version
        drop(branch); // Stop mutable RefCell borrow since GC might borrow branch for marking
        block = gen_block_series(target_blockid, &target_ctx, ec, cb);
        branch = branch_rc.borrow_mut();

        if block.is_none() && branch_modified {
            // We couldn't generate a new block for the branch, but we modified the branch.
            // Restore the branch by regenerating it.
            branch.gen_fn.set_shape(branch_old_shape);
            regenerate_branch(cb, &mut branch);
        }
    }

    // Finish building the new block
    let dst_addr = match block {
        Some(block_rc) => {
            let mut block: RefMut<_> = block_rc.borrow_mut();

            // Branch shape should reflect layout
            assert!(
                !(branch.gen_fn.get_shape() == target_branch_shape
                    && Some(block.start_addr) != branch.end_addr)
            );

            // Add this branch to the list of incoming branches for the target
            block.push_incoming(branch_rc.clone());
            mem::drop(block); // end mut borrow

            // Update the branch target address
            branch.targets[target_idx] = Some(Box::new(BranchTarget::Block(block_rc.clone())));

            // Rewrite the branch with the new jump target address
            regenerate_branch(cb, &mut branch);

            // Restore interpreter sp, since the code hitting the stub expects the original.
            unsafe { rb_set_cfp_sp(cfp, original_interp_sp) };

            block_rc.borrow().start_addr
        }
        None => {
            // Code GC needs to borrow blocks for invalidation, so their mutable
            // borrows must be dropped first.
            drop(block);
            drop(branch);
            // Trigger code GC. The whole ISEQ will be recompiled later.
            // We shouldn't trigger it in the middle of compilation in branch_stub_hit
            // because incomplete code could be used when cb.dropped_bytes is flipped
            // by code GC. So this place, after all compilation, is the safest place
            // to hook code GC on branch_stub_hit.
            cb.code_gc();
            branch = branch_rc.borrow_mut();

            // Failed to service the stub by generating a new block so now we
            // need to exit to the interpreter at the stubbed location. We are
            // intentionally *not* restoring original_interp_sp. At the time of
            // writing, reconstructing interpreter state only involves setting
            // cfp->sp and cfp->pc. We set both before trying to generate the
            // block. All there is left to do to exit is to pop the native
            // frame. We do that in code_for_exit_from_stub.
            CodegenGlobals::get_stub_exit_code()
        }
    };

    CodegenGlobals::with_outlined_cb(|ocb| {
        ocb.unwrap().mark_all_executable();
    });

    cb.mark_all_executable();

    let new_branch_size = branch.code_size();
    assert!(
        new_branch_size <= branch_size_on_entry,
        "branch stubs should never enlarge branches (start_addr: {:?}, old_size: {}, new_size: {})",
        branch.start_addr.unwrap().raw_ptr(),
        branch_size_on_entry,
        new_branch_size,
    );

    // Return a pointer to the compiled block version
    dst_addr.raw_ptr()
}

/// Set up a branch target at an index with a block version or a stub
pub fn set_branch_target(
    target_idx: u32,
    target: BlockId,
    ctx: &Context,
    branchref: &BranchRef,
    branch: &mut Branch,
    ocb: &mut OutlinedCb,
) {
    let maybe_block = find_block_version(target, ctx);

    // If the block already exists
    if let Some(blockref) = maybe_block {
        let mut block = blockref.borrow_mut();

        // Add an incoming branch into this block
        block.push_incoming(branchref.clone());

        // Fill out the target with this block
        branch.targets[target_idx.into_usize()] =
            Some(Box::new(BranchTarget::Block(blockref.clone())));

        return;
    }

    let ocb = ocb.unwrap();

    // Generate an outlined stub that will call branch_stub_hit()
    let stub_addr = ocb.get_write_ptr();

    // Get a raw pointer to the branch. We clone and then decrement the strong count which overall
    // balances the strong count. We do this so that we're passing the result of [Rc::into_raw] to
    // [Rc::from_raw] as required.
    // We make sure the block housing the branch is still alive when branch_stub_hit() is running.
    let branch_ptr: *const RefCell<Branch> = BranchRef::into_raw(branchref.clone());
    unsafe { BranchRef::decrement_strong_count(branch_ptr) };

    let mut asm = Assembler::new();
    asm.comment("branch stub hit");

    // Set up the arguments unique to this stub for:
    // branch_stub_hit(branch_ptr, target_idx, ec)
    asm.mov(C_ARG_OPNDS[0], Opnd::const_ptr(branch_ptr as *const u8));
    asm.mov(C_ARG_OPNDS[1], target_idx.into());

    // Jump to trampoline to call branch_stub_hit()
    // Not really a side exit, just don't need a padded jump here.
    asm.jmp(CodegenGlobals::get_branch_stub_hit_trampoline().as_side_exit());

    asm.compile(ocb);

    if ocb.has_dropped_bytes() {
        // No space
    } else {
        // Fill the branch target with a stub
        branch.targets[target_idx.into_usize()] =
            Some(Box::new(BranchTarget::Stub(Box::new(BranchStub {
                address: Some(stub_addr),
                id: target,
                ctx: ctx.clone(),
            }))));
    }
}

pub fn gen_branch_stub_hit_trampoline(ocb: &mut OutlinedCb) -> CodePtr {
    let ocb = ocb.unwrap();
    let code_ptr = ocb.get_write_ptr();
    let mut asm = Assembler::new();

    // For `branch_stub_hit(branch_ptr, target_idx, ec)`,
    // `branch_ptr` and `target_idx` is different for each stub,
    // but the call and what's after is the same. This trampoline
    // is the unchanging part.
    // Since this trampoline is static, it allows code GC inside
    // branch_stub_hit() to free stubs without problems.
    asm.comment("branch_stub_hit() trampoline");
    let jump_addr = asm.ccall(
        branch_stub_hit as *mut u8,
        vec![C_ARG_OPNDS[0], C_ARG_OPNDS[1], EC],
    );

    // Jump to the address returned by the branch_stub_hit() call
    asm.jmp_opnd(jump_addr);

    asm.compile(ocb);

    code_ptr
}

impl Assembler {
    // Mark the start position of a patchable branch in the machine code
    pub fn mark_branch_start(&mut self, branchref: &BranchRef) {
        // We need to create our own branch rc object
        // so that we can move the closure below
        let branchref = branchref.clone();

        self.pos_marker(move |code_ptr| {
            let mut branch = branchref.borrow_mut();
            branch.start_addr = Some(code_ptr);
        });
    }

    // Mark the end position of a patchable branch in the machine code
    pub fn mark_branch_end(&mut self, branchref: &BranchRef) {
        // We need to create our own branch rc object
        // so that we can move the closure below
        let branchref = branchref.clone();

        self.pos_marker(move |code_ptr| {
            let mut branch = branchref.borrow_mut();
            branch.end_addr = Some(code_ptr);
        });
    }
}

pub fn gen_branch(
    code_generator: &mut CodeGenerator,
    target0: BlockId,
    ctx0: &Context,
    target1: Option<BlockId>,
    ctx1: Option<&Context>,
    gen_fn: BranchGenFn,
) {
    let block_ref = code_generator.jit.get_block();
    let branchref = make_branch_entry(&mut code_generator.jit, &block_ref, gen_fn);
    let branch = &mut branchref.borrow_mut();

    // Get the branch targets or stubs
    set_branch_target(
        0,
        target0,
        ctx0,
        &branchref,
        branch,
        code_generator.get_ocb(),
    );
    if let Some(ctx) = ctx1 {
        set_branch_target(
            1,
            target1.unwrap(),
            ctx,
            &branchref,
            branch,
            code_generator.get_ocb(),
        );
        if branch.targets[1].is_none() {
            return; // avoid unwrap() in gen_fn()
        }
    }

    // Call the branch generation function
    code_generator.asm.mark_branch_start(&branchref);
    if let Some(dst_addr) = branch.get_target_address(0) {
        gen_fn.call(
            &mut code_generator.asm,
            dst_addr,
            branch.get_target_address(1),
        );
    }
    code_generator.asm.mark_branch_end(&branchref);
}

pub fn gen_direct_jump(jit: &mut JITState, ctx: &Context, target0: BlockId, asm: &mut Assembler) {
    let branchref = make_branch_entry(
        jit,
        &jit.get_block(),
        BranchGenFn::JumpToTarget0(BranchShape::Default),
    );
    let mut branch = branchref.borrow_mut();

    let mut new_target = BranchTarget::Stub(Box::new(BranchStub {
        address: None,
        ctx: ctx.clone(),
        id: target0,
    }));

    let maybe_block = find_block_version(target0, ctx);

    // If the block already exists
    if let Some(blockref) = maybe_block {
        let mut block = blockref.borrow_mut();
        let block_addr = block.start_addr;

        block.push_incoming(branchref.clone());

        new_target = BranchTarget::Block(blockref.clone());

        branch.gen_fn.set_shape(BranchShape::Default);

        // Call the branch generation function
        asm.comment("gen_direct_jmp: existing block");
        asm.mark_branch_start(&branchref);
        branch.gen_fn.call(asm, block_addr, None);
        asm.mark_branch_end(&branchref);
    } else {
        // `None` in new_target.address signals gen_block_series() to compile the
        // target block right after this one (fallthrough).
        branch.gen_fn.set_shape(BranchShape::Next0);

        // The branch is effectively empty (a noop)
        asm.comment("gen_direct_jmp: fallthrough");
        asm.mark_branch_start(&branchref);
        asm.mark_branch_end(&branchref);
    }

    branch.targets[0] = Some(Box::new(new_target));
}

fn remove_from_graph(blockref: &BlockRef) {
    let block = blockref.borrow();

    // Remove this block from the predecessor's targets
    for pred_branchref in &block.incoming {
        // Branch from the predecessor to us
        let mut pred_branch = pred_branchref.borrow_mut();

        // If this is us, nullify the target block
        for target_idx in 0..=1 {
            if let Some(target) = pred_branch.targets[target_idx].as_ref() {
                if target.get_block().as_ref() == Some(blockref) {
                    pred_branch.targets[target_idx] = None;
                }
            }
        }
    }

    // For each outgoing branch
    for out_branchref in block.outgoing.iter() {
        let out_branch = out_branchref.borrow();

        // For each successor block
        for out_target in out_branch.targets.iter().flatten() {
            if let Some(succ_blockref) = &out_target.get_block() {
                // Remove outgoing branch from the successor's incoming list
                let mut succ_block = succ_blockref.borrow_mut();
                succ_block
                    .incoming
                    .retain(|succ_incoming| !Rc::ptr_eq(succ_incoming, out_branchref));
            }
        }
    }
}

/// Remove most references to a block to deallocate it.
/// Does not touch references from iseq payloads.
pub fn free_block(blockref: &BlockRef) {
    block_assumptions_free(blockref);

    remove_from_graph(blockref);

    // Branches have a Rc pointing at the block housing them.
    // Break the cycle.
    blockref.borrow_mut().incoming.clear();
    blockref.borrow_mut().outgoing = Box::new([]);

    // No explicit deallocation here as blocks are ref-counted.
}

// Some runtime checks for integrity of a program location
pub fn verify_blockid(blockid: BlockId) {
    unsafe {
        assert!(rb_IMEMO_TYPE_P(blockid.iseq.into(), imemo_iseq) != 0);
        assert!(blockid.idx < get_iseq_encoded_size(blockid.iseq));
    }
}

// Invalidate one specific block version
pub fn invalidate_block_version(blockref: &BlockRef) {
    //ASSERT_vm_locking();

    // TODO: want to assert that all other ractors are stopped here. Can't patch
    // machine code that some other thread is running.

    let block = blockref.borrow();
    let cb = CodegenGlobals::get_inline_cb();

    verify_blockid(block.blockid);

    #[cfg(feature = "disasm")]
    {
        use crate::dev::options::get_option_ref;
        use crate::utils::iseq_get_location;
        // If dump_iseq_disasm is specified, print to console that blocks for matching ISEQ names were invalidated.
        if let Some(substr) = get_option_ref!(dump_iseq_disasm).as_ref() {
            let blockid_idx = block.blockid.idx;
            let iseq_location = iseq_get_location(block.blockid.iseq, blockid_idx);
            if iseq_location.contains(substr) {
                println!(
                    "Invalidating block from {}, ISEQ offsets [{}, {})",
                    iseq_location, blockid_idx, block.end_idx
                );
            }
        }
    }

    // Remove this block from the version array
    remove_block_version(blockref);

    // Get a pointer to the generated code for this block
    let block_start = block.start_addr;

    // Make the the start of the block do an exit. This handles OOM situations
    // and some cases where we can't efficiently patch incoming branches.
    // Do this first, since in case there is a fallthrough branch into this
    // block, the patching loop below can overwrite the start of the block.
    // In those situations, there is hopefully no jumps to the start of the block
    // after patching as the start of the block would be in the middle of something
    // generated by branch_t::gen_fn.
    let block_entry_exit = block
        .entry_exit
        .expect("invalidation needs the entry_exit field");
    {
        let block_end = block
            .end_addr
            .expect("invalidation needs constructed block");

        if block_start == block_entry_exit {
            // Some blocks exit on entry. Patching a jump to the entry at the
            // entry makes an infinite loop.
        } else {
            // Patch in a jump to block.entry_exit.

            let cur_pos = cb.get_write_ptr();
            let cur_dropped_bytes = cb.has_dropped_bytes();
            cb.set_write_ptr(block_start);

            let mut asm = Assembler::new();
            asm.jmp(block_entry_exit.as_side_exit());
            cb.set_dropped_bytes(false);
            asm.compile(cb);

            assert!(
                cb.get_write_ptr() <= block_end,
                "invalidation wrote past end of block (code_size: {:?}, new_size: {})",
                block.code_size(),
                cb.get_write_ptr().into_i64() - block_start.into_i64(),
            );
            cb.set_write_ptr(cur_pos);
            cb.set_dropped_bytes(cur_dropped_bytes);
        }
    }

    // For each incoming branch
    mem::drop(block); // end borrow: regenerate_branch might mut borrow this
    let block = blockref.borrow().clone();
    for branchref in &block.incoming {
        let mut branch = branchref.borrow_mut();

        let target_idx = if branch.get_target_address(0) == Some(block_start) {
            0
        } else {
            1
        };

        // Assert that the incoming branch indeed points to the block being invalidated
        let incoming_target = branch.targets[target_idx].as_ref().unwrap();
        assert_eq!(Some(block_start), incoming_target.get_address());
        if let Some(incoming_block) = &incoming_target.get_block() {
            assert_eq!(blockref, incoming_block);
        }

        CodegenGlobals::with_outlined_cb(|ocb| {
            // Create a stub for this branch target or rewire it to a valid block
            set_branch_target(
                target_idx as u32,
                block.blockid,
                &block.ctx,
                branchref,
                &mut branch,
                ocb,
            );
        });

        if branch.targets[target_idx].is_none() {
            // We were unable to generate a stub (e.g. OOM). Use the block's
            // exit instead of a stub for the block. It's important that we
            // still patch the branch in this situation so stubs are unique
            // to branches. Think about what could go wrong if we run out of
            // memory in the middle of this loop.
            branch.targets[target_idx] = Some(Box::new(BranchTarget::Stub(Box::new(BranchStub {
                address: block.entry_exit,
                id: block.blockid,
                ctx: block.ctx.clone(),
            }))));
        }

        // Check if the invalidated block immediately follows
        let target_next = Some(block.start_addr) == branch.end_addr;

        if target_next {
            // The new block will no longer be adjacent.
            // Note that we could be enlarging the branch and writing into the
            // start of the block being invalidated.
            branch.gen_fn.set_shape(BranchShape::Default);
        }

        // Rewrite the branch with the new jump target address
        let old_branch_size = branch.code_size();
        regenerate_branch(cb, &mut branch);

        if target_next && branch.end_addr > block.end_addr {
            panic!("yjit invalidate rewrote branch past end of invalidated block: {:?} (code_size: {})", branch, block.code_size());
        }
        if !target_next && branch.code_size() > old_branch_size {
            panic!(
                "invalidated branch grew in size (start_addr: {:?}, old_size: {}, new_size: {})",
                branch.start_addr.unwrap().raw_ptr(),
                old_branch_size,
                branch.code_size()
            );
        }
    }

    // Clear out the JIT func so that we can recompile later and so the
    // interpreter will run the iseq.
    //
    // Only clear the jit_func when we're invalidating the JIT entry block.
    // We only support compiling iseqs from index 0 right now.  So entry
    // points will always have an instruction index of 0.  We'll need to
    // change this in the future when we support optional parameters because
    // they enter the function with a non-zero PC
    if block.blockid.idx == 0 {
        // TODO:
        // We could reset the exec counter to zero in rb_iseq_reset_jit_func()
        // so that we eventually compile a new entry point when useful
        unsafe { rb_iseq_reset_jit_func(block.blockid.iseq) };
    }

    // FIXME:
    // Call continuation addresses on the stack can also be atomically replaced by jumps going to the stub.

    delayed_deallocation(blockref);

    CodegenGlobals::with_outlined_cb(|ocb| {
        ocb.unwrap().mark_all_executable();
    });
    cb.mark_all_executable();

    incr_counter!(invalidation_count);
}

// We cannot deallocate blocks immediately after invalidation since there
// could be stubs waiting to access branch pointers. Return stubs can do
// this since patching the code for setting up return addresses does not
// affect old return addresses that are already set up to use potentially
// invalidated branch pointers. Example:
//   def foo(n)
//     if n == 2
//       return 1.times { Object.define_method(:foo) {} }
//     end
//
//     foo(n + 1)
//   end
//   p foo(1)
pub fn delayed_deallocation(blockref: &BlockRef) {
    block_assumptions_free(blockref);

    // We do this another time when we deem that it's safe
    // to deallocate in case there is another Ractor waiting to acquire the
    // VM lock inside branch_stub_hit().
    remove_from_graph(blockref);

    let payload = get_iseq_payload(blockref.borrow().blockid.iseq).unwrap();
    payload.dead_blocks.push(blockref.clone());
}

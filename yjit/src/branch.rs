use std::{
    cell::{RefCell, RefMut},
    ffi::c_void,
    mem,
    rc::Rc,
};

use crate::{
    asm::{CodeBlock, OutlinedCb},
    backend::ir::{Assembler, Opnd, C_ARG_OPNDS, EC},
    bbv::find_block_version,
    codegen::{generator::CodeGenerator, globals::CodegenGlobals, CodePtr},
    core::gen_block_series,
    cruby::{
        get_cfp_sp, get_ec_cfp, rb_cfp_get_iseq, rb_iseq_pc_at_idx, rb_set_cfp_pc, rb_set_cfp_sp,
        src_loc, with_vm_lock, EcPtr,
    },
    dev::{options::get_option, stats::incr_counter},
    meta::{
        block::{
            BlockId, BlockRef, Branch, BranchGenFn, BranchRef, BranchShape, BranchStub,
            BranchTarget,
        },
        context::Context,
        jit_state::JITState,
    },
    utils::{c_callable, IntoUsize},
};

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

/// Generate code for a branch, possibly rewriting and changing the size of it
pub fn regenerate_branch(cb: &mut CodeBlock, branch: &mut Branch) {
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

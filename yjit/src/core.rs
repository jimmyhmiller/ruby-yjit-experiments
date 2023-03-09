use crate::{
    asm::{CodeBlock, OutlinedCb},
    backend::ir::{Assembler, Opnd, C_ARG_OPNDS, EC},
    block::{
        BlockId, BlockRef, Branch, BranchGenFn, BranchRef, BranchShape, BranchStub, BranchTarget,
        IseqPayload, VersionList,
    },
    codegen::{gen_entry_prologue, gen_single_block, CodeGenerator, CodegenGlobals},
    context::{Context, TypeDiff},
    cruby::{
        get_cfp_pc, get_cfp_sp, get_ec_cfp, get_iseq_encoded_size, imemo_iseq, obj_written,
        rb_IMEMO_TYPE_P, rb_cfp_get_iseq, rb_gc_location, rb_gc_mark_movable,
        rb_iseq_get_yjit_payload, rb_iseq_pc_at_idx, rb_iseq_reset_jit_func,
        rb_iseq_set_yjit_payload, rb_jit_cont_each_iseq, rb_set_cfp_pc, rb_set_cfp_sp,
        rb_vm_barrier, rb_yjit_for_each_iseq, rb_yjit_obj_written, src_loc, with_vm_lock, EcPtr,
        IseqPtr, VALUE,
    },
    invariants::block_assumptions_free,
    jit_state::JITState,
    options::get_option,
    stats::incr_counter,
    utils::{c_callable, IntoUsize},
    virtualmem::CodePtr,
};

use core::ffi::c_void;
use std::cell::{RefCell, RefMut};
use std::mem;
use std::rc::Rc;

#[cfg(feature = "disasm")]
use crate::disasm::*;

// Operand to a YARV bytecode instruction
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum YARVOpnd {
    // The value is self
    SelfOpnd,

    // Temporary stack operand with stack index
    StackOpnd(u8),
}

impl From<Opnd> for YARVOpnd {
    fn from(value: Opnd) -> Self {
        match value {
            Opnd::Stack { idx, .. } => YARVOpnd::StackOpnd(idx.try_into().unwrap()),
            _ => unreachable!("{:?} cannot be converted to YARVOpnd", value),
        }
    }
}

/// Get the payload for an iseq. For safety it's up to the caller to ensure the returned `&mut`
/// upholds aliasing rules and that the argument is a valid iseq.
pub fn get_iseq_payload(iseq: IseqPtr) -> Option<&'static mut IseqPayload> {
    let payload = unsafe { rb_iseq_get_yjit_payload(iseq) };
    let payload: *mut IseqPayload = payload.cast();
    unsafe { payload.as_mut() }
}

/// Get the payload object associated with an iseq. Create one if none exists.
pub fn get_or_create_iseq_payload(iseq: IseqPtr) -> &'static mut IseqPayload {
    type VoidPtr = *mut c_void;

    let payload_non_null = unsafe {
        let payload = rb_iseq_get_yjit_payload(iseq);
        if payload.is_null() {
            // Increment the compiled iseq count
            incr_counter!(compiled_iseq_count);

            // Allocate a new payload with Box and transfer ownership to the GC.
            // We drop the payload with Box::from_raw when the GC frees the iseq and calls us.
            // NOTE(alan): Sometimes we read from an iseq without ever writing to it.
            // We allocate in those cases anyways.
            let new_payload = IseqPayload::default();
            let new_payload = Box::into_raw(Box::new(new_payload));
            rb_iseq_set_yjit_payload(iseq, new_payload as VoidPtr);

            new_payload
        } else {
            payload as *mut IseqPayload
        }
    };

    // SAFETY: we should have the VM lock and all other Ruby threads should be asleep. So we have
    // exclusive mutable access.
    // Hmm, nothing seems to stop calling this on the same
    // iseq twice, though, which violates aliasing rules.
    unsafe { payload_non_null.as_mut() }.unwrap()
}

/// Iterate over all existing ISEQs
pub fn for_each_iseq<F: FnMut(IseqPtr)>(mut callback: F) {
    unsafe extern "C" fn callback_wrapper(iseq: IseqPtr, data: *mut c_void) {
        let callback: &mut &mut dyn FnMut(IseqPtr) -> bool = std::mem::transmute(&mut *data);
        callback(iseq);
    }
    let mut data: &mut dyn FnMut(IseqPtr) = &mut callback;
    unsafe { rb_yjit_for_each_iseq(Some(callback_wrapper), (&mut data) as *mut _ as *mut c_void) };
}

/// Iterate over all ISEQ payloads
pub fn for_each_iseq_payload<F: FnMut(&IseqPayload)>(mut callback: F) {
    for_each_iseq(|iseq| {
        if let Some(iseq_payload) = get_iseq_payload(iseq) {
            callback(iseq_payload);
        }
    });
}

/// Iterate over all on-stack ISEQs
pub fn for_each_on_stack_iseq<F: FnMut(IseqPtr)>(mut callback: F) {
    unsafe extern "C" fn callback_wrapper(iseq: IseqPtr, data: *mut c_void) {
        let callback: &mut &mut dyn FnMut(IseqPtr) -> bool = std::mem::transmute(&mut *data);
        callback(iseq);
    }
    let mut data: &mut dyn FnMut(IseqPtr) = &mut callback;
    unsafe { rb_jit_cont_each_iseq(Some(callback_wrapper), (&mut data) as *mut _ as *mut c_void) };
}

/// Iterate over all on-stack ISEQ payloads
pub fn for_each_on_stack_iseq_payload<F: FnMut(&IseqPayload)>(mut callback: F) {
    for_each_on_stack_iseq(|iseq| {
        if let Some(iseq_payload) = get_iseq_payload(iseq) {
            callback(iseq_payload);
        }
    });
}

/// Iterate over all NOT on-stack ISEQ payloads
pub fn for_each_off_stack_iseq_payload<F: FnMut(&mut IseqPayload)>(mut callback: F) {
    let mut on_stack_iseqs: Vec<IseqPtr> = vec![];
    for_each_on_stack_iseq(|iseq| {
        on_stack_iseqs.push(iseq);
    });
    for_each_iseq(|iseq| {
        if !on_stack_iseqs.contains(&iseq) {
            if let Some(iseq_payload) = get_iseq_payload(iseq) {
                callback(iseq_payload);
            }
        }
    })
}

/// Free the per-iseq payload
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_free(payload: *mut c_void) {
    let payload = {
        if payload.is_null() {
            // Nothing to free.
            return;
        } else {
            payload as *mut IseqPayload
        }
    };

    // Take ownership of the payload with Box::from_raw().
    // It drops right before this function returns.
    // SAFETY: We got the pointer from Box::into_raw().
    let payload = unsafe { Box::from_raw(payload) };

    // Increment the freed iseq count
    incr_counter!(freed_iseq_count);

    // Free all blocks in the payload
    for versions in &payload.version_map {
        for block in versions {
            free_block(block);
        }
    }
}

/// GC callback for marking GC objects in the the per-iseq payload.
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_mark(payload: *mut c_void) {
    let payload = if payload.is_null() {
        // Nothing to mark.
        return;
    } else {
        // SAFETY: It looks like the GC takes the VM lock while marking
        // so we should be satisfying aliasing rules here.
        unsafe { &*(payload as *const IseqPayload) }
    };

    // For marking VALUEs written into the inline code block.
    // We don't write VALUEs in the outlined block.
    let cb: &CodeBlock = CodegenGlobals::get_inline_cb();

    for versions in &payload.version_map {
        for block in versions {
            let block = block.borrow();

            unsafe { rb_gc_mark_movable(block.blockid.iseq.into()) };

            // Mark method entry dependencies
            for &cme_dep in block.cme_dependencies.iter() {
                unsafe { rb_gc_mark_movable(cme_dep.into()) };
            }

            // Mark outgoing branch entries
            for branch in block.outgoing.iter() {
                let branch = branch.borrow();
                for target in branch.targets.iter().flatten() {
                    unsafe { rb_gc_mark_movable(target.get_blockid().iseq.into()) };
                }
            }

            // Walk over references to objects in generated code.
            for offset in block.gc_obj_offsets.iter() {
                let value_address: *const u8 = cb.get_ptr(offset.into_usize()).raw_ptr();
                // Creating an unaligned pointer is well defined unlike in C.
                let value_address = value_address as *const VALUE;

                // SAFETY: these point to YJIT's code buffer
                unsafe {
                    let object = value_address.read_unaligned();
                    rb_gc_mark_movable(object);
                };
            }
        }
    }
}

/// GC callback for updating GC objects in the the per-iseq payload.
/// This is a mirror of [rb_yjit_iseq_mark].
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_update_references(payload: *mut c_void) {
    let payload = if payload.is_null() {
        // Nothing to update.
        return;
    } else {
        // SAFETY: It looks like the GC takes the VM lock while updating references
        // so we should be satisfying aliasing rules here.
        unsafe { &*(payload as *const IseqPayload) }
    };

    // Evict other threads from generated code since we are about to patch them.
    // Also acts as an assert that we hold the VM lock.
    unsafe { rb_vm_barrier() };

    // For updating VALUEs written into the inline code block.
    let cb = CodegenGlobals::get_inline_cb();

    for versions in &payload.version_map {
        for version in versions {
            let mut block = version.borrow_mut();

            block.blockid.iseq = unsafe { rb_gc_location(block.blockid.iseq.into()) }.as_iseq();

            // Update method entry dependencies
            for cme_dep in block.cme_dependencies.iter_mut() {
                *cme_dep = unsafe { rb_gc_location((*cme_dep).into()) }.as_cme();
            }

            // Walk over references to objects in generated code.
            for offset in block.gc_obj_offsets.iter() {
                let offset_to_value = offset.into_usize();
                let value_code_ptr = cb.get_ptr(offset_to_value);
                let value_ptr: *const u8 = value_code_ptr.raw_ptr();
                // Creating an unaligned pointer is well defined unlike in C.
                let value_ptr = value_ptr as *mut VALUE;

                // SAFETY: these point to YJIT's code buffer
                let object = unsafe { value_ptr.read_unaligned() };
                let new_addr = unsafe { rb_gc_location(object) };

                // Only write when the VALUE moves, to be copy-on-write friendly.
                if new_addr != object {
                    for (byte_idx, &byte) in new_addr.as_u64().to_le_bytes().iter().enumerate() {
                        let byte_code_ptr = value_code_ptr.add_bytes(byte_idx);
                        cb.write_mem(byte_code_ptr, byte)
                            .expect("patching existing code should be within bounds");
                    }
                }
            }

            // Update outgoing branch entries
            let outgoing_branches = block.outgoing.clone(); // clone to use after borrow
            mem::drop(block); // end mut borrow: target.set_iseq and target.get_blockid() might (mut) borrow it
            for branch in outgoing_branches.iter() {
                let mut branch = branch.borrow_mut();
                for target in branch.targets.iter_mut().flatten() {
                    target.set_iseq(
                        unsafe { rb_gc_location(target.get_blockid().iseq.into()) }.as_iseq(),
                    );
                }
            }
        }
    }

    // Note that we would have returned already if YJIT is off.
    cb.mark_all_executable();

    CodegenGlobals::get_outlined_cb()
        .unwrap()
        .mark_all_executable();
}

/// Get all blocks for a particular place in an iseq.
fn get_version_list(blockid: BlockId) -> Option<&'static mut VersionList> {
    let insn_idx = blockid.idx.into_usize();
    match get_iseq_payload(blockid.iseq) {
        Some(payload) if insn_idx < payload.version_map.len() => {
            Some(payload.version_map.get_mut(insn_idx).unwrap())
        }
        _ => None,
    }
}

/// Get or create all blocks for a particular place in an iseq.
fn get_or_create_version_list(blockid: BlockId) -> &'static mut VersionList {
    let payload = get_or_create_iseq_payload(blockid.iseq);
    let insn_idx = blockid.idx.into_usize();

    // Expand the version map as necessary
    if insn_idx >= payload.version_map.len() {
        payload
            .version_map
            .resize(insn_idx + 1, VersionList::default());
    }

    return payload.version_map.get_mut(insn_idx).unwrap();
}

/// Take all of the blocks for a particular place in an iseq
pub fn take_version_list(blockid: BlockId) -> VersionList {
    let insn_idx = blockid.idx.into_usize();
    match get_iseq_payload(blockid.iseq) {
        Some(payload) if insn_idx < payload.version_map.len() => {
            mem::take(&mut payload.version_map[insn_idx])
        }
        _ => VersionList::default(),
    }
}

/// Count the number of block versions matching a given blockid
fn get_num_versions(blockid: BlockId) -> usize {
    let insn_idx = blockid.idx.into_usize();
    match get_iseq_payload(blockid.iseq) {
        Some(payload) => payload
            .version_map
            .get(insn_idx)
            .map(|versions| versions.len())
            .unwrap_or(0),
        None => 0,
    }
}

/// Get or create a list of block versions generated for an iseq
/// This is used for disassembly (see disasm.rs)
pub fn get_or_create_iseq_block_list(iseq: IseqPtr) -> Vec<BlockRef> {
    let payload = get_or_create_iseq_payload(iseq);

    let mut blocks = Vec::<BlockRef>::new();

    // For each instruction index
    for insn_idx in 0..payload.version_map.len() {
        let version_list = &payload.version_map[insn_idx];

        // For each version at this instruction index
        for version in version_list {
            // Clone the block ref and add it to the list
            blocks.push(version.clone());
        }
    }

    blocks
}

/// Retrieve a basic block version for an (iseq, idx) tuple
/// This will return None if no version is found
fn find_block_version(blockid: BlockId, ctx: &Context) -> Option<BlockRef> {
    let versions = match get_version_list(blockid) {
        Some(versions) => versions,
        None => return None,
    };

    // Best match found
    let mut best_version: Option<BlockRef> = None;
    let mut best_diff = usize::MAX;

    // For each version matching the blockid
    for blockref in versions.iter_mut() {
        let block = blockref.borrow();
        // Note that we always prefer the first matching
        // version found because of inline-cache chains
        match ctx.diff(&block.ctx) {
            TypeDiff::Compatible(diff) if diff < best_diff => {
                best_version = Some(blockref.clone());
                best_diff = diff;
            }
            _ => {}
        }
    }

    // If greedy versioning is enabled
    if get_option!(greedy_versioning) {
        // If we're below the version limit, don't settle for an imperfect match
        if versions.len() + 1 < get_option!(max_versions) && best_diff > 0 {
            return None;
        }
    }

    best_version
}

/// Produce a generic context when the block version limit is hit for a blockid
pub fn limit_block_versions(blockid: BlockId, ctx: &Context) -> Context {
    // Guard chains implement limits separately, do nothing
    if ctx.chain_depth > 0 {
        return ctx.clone();
    }

    // If this block version we're about to add will hit the version limit
    if get_num_versions(blockid) + 1 >= get_option!(max_versions) {
        // Produce a generic context that stores no type information,
        // but still respects the stack_size and sp_offset constraints.
        // This new context will then match all future requests.
        let generic_ctx = Context {
            stack_size: ctx.stack_size,
            sp_offset: ctx.sp_offset,
            ..Default::default()
        };

        debug_assert_ne!(
            TypeDiff::Incompatible,
            ctx.diff(&generic_ctx),
            "should substitute a compatible context",
        );

        return generic_ctx;
    }

    ctx.clone()
}

/// Keep track of a block version. Block should be fully constructed.
/// Uses `cb` for running write barriers.
fn add_block_version(blockref: &BlockRef, cb: &CodeBlock) {
    let block = blockref.borrow();

    // Function entry blocks must have stack size 0
    assert!(!(block.blockid.idx == 0 && block.ctx.stack_size > 0));

    let version_list = get_or_create_version_list(block.blockid);

    version_list.push(blockref.clone());
    version_list.shrink_to_fit();

    // By writing the new block to the iseq, the iseq now
    // contains new references to Ruby objects. Run write barriers.
    let iseq: VALUE = block.blockid.iseq.into();
    for &dep in block.iter_cme_deps() {
        obj_written!(iseq, dep.into());
    }

    // Run write barriers for all objects in generated code.
    for offset in block.gc_obj_offsets.iter() {
        let value_address: *const u8 = cb.get_ptr(offset.into_usize()).raw_ptr();
        // Creating an unaligned pointer is well defined unlike in C.
        let value_address: *const VALUE = value_address.cast();

        let object = unsafe { value_address.read_unaligned() };
        obj_written!(iseq, object);
    }

    incr_counter!(compiled_block_count);

    // Mark code pages for code GC
    let iseq_payload = get_iseq_payload(block.blockid.iseq).unwrap();
    for page in cb.addrs_to_pages(block.start_addr, block.end_addr.unwrap()) {
        iseq_payload.pages.insert(page);
    }
}

/// Remove a block version from the version map of its parent ISEQ
fn remove_block_version(blockref: &BlockRef) {
    let block = blockref.borrow();
    let version_list = match get_version_list(block.blockid) {
        Some(version_list) => version_list,
        None => return,
    };

    // Retain the versions that are not this one
    version_list.retain(|other| blockref != other);
}

/// See [gen_block_series_body]. This simply counts compilation failures.
fn gen_block_series(
    blockid: BlockId,
    start_ctx: &Context,
    ec: EcPtr,
    cb: &mut CodeBlock,
    ocb: &mut OutlinedCb,
) -> Option<BlockRef> {
    let result = gen_block_series_body(blockid, start_ctx, ec, cb, ocb);
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
    ocb: &mut OutlinedCb,
) -> Option<BlockRef> {
    // Keep track of all blocks compiled in this batch
    const EXPECTED_BATCH_SIZE: usize = 4;
    let mut batch = Vec::with_capacity(EXPECTED_BATCH_SIZE);

    // Generate code for the first block
    let first_block = gen_single_block(blockid, start_ctx, ec, cb, ocb).ok()?;
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
        let result = gen_single_block(requested_blockid, &requested_ctx, ec, cb, ocb);

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
        use crate::options::get_option_ref;
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
    let ocb = CodegenGlobals::get_outlined_cb();

    // Write the interpreter entry prologue. Might be NULL when out of memory.
    let code_ptr = gen_entry_prologue(cb, iseq, insn_idx);

    // Try to generate code for the entry block
    let block = gen_block_series(blockid, &Context::default(), ec, cb, ocb);

    cb.mark_all_executable();
    ocb.unwrap().mark_all_executable();

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
    let ocb = CodegenGlobals::get_outlined_cb();

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
        block = gen_block_series(target_blockid, &target_ctx, ec, cb, ocb);
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

    ocb.unwrap().mark_all_executable();
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
    let ocb = CodegenGlobals::get_outlined_cb();

    verify_blockid(block.blockid);

    #[cfg(feature = "disasm")]
    {
        use crate::options::get_option_ref;
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

        // Create a stub for this branch target or rewire it to a valid block
        set_branch_target(
            target_idx as u32,
            block.blockid,
            &block.ctx,
            branchref,
            &mut branch,
            ocb,
        );

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

    ocb.unwrap().mark_all_executable();
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

#[cfg(test)]
mod tests {
    use crate::{
        context::Type,
        core::{Context, TypeDiff, YARVOpnd},
    };

    #[test]
    fn types() {
        // Valid src => dst
        assert_eq!(Type::Unknown.diff(Type::Unknown), TypeDiff::Compatible(0));
        assert_eq!(
            Type::UnknownImm.diff(Type::UnknownImm),
            TypeDiff::Compatible(0)
        );
        assert_ne!(Type::UnknownImm.diff(Type::Unknown), TypeDiff::Incompatible);
        assert_ne!(Type::Fixnum.diff(Type::Unknown), TypeDiff::Incompatible);
        assert_ne!(Type::Fixnum.diff(Type::UnknownImm), TypeDiff::Incompatible);

        // Invalid src => dst
        assert_eq!(Type::Unknown.diff(Type::UnknownImm), TypeDiff::Incompatible);
        assert_eq!(Type::Unknown.diff(Type::Fixnum), TypeDiff::Incompatible);
        assert_eq!(Type::Fixnum.diff(Type::UnknownHeap), TypeDiff::Incompatible);
    }

    #[test]
    fn context() {
        // Valid src => dst
        assert_eq!(
            Context::default().diff(&Context::default()),
            TypeDiff::Compatible(0)
        );

        // Try pushing an operand and getting its type
        let mut ctx = Context::default();
        ctx.stack_push(Type::Fixnum);
        let top_type = ctx.get_opnd_type(YARVOpnd::StackOpnd(0));
        assert!(top_type == Type::Fixnum);

        // TODO: write more tests for Context type diff
    }
}

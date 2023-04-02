use crate::{
    asm::CodeBlock,
    backend::ir::{Assembler, Opnd, CFP, C_ARG_OPNDS, EC, SP},
    bbv::{add_block_version, remove_block_version},
    codegen::{generator::CodeGenerator, globals::CodegenGlobals, old_gen_pc_guard},
    cruby::{
        get_cfp_pc, get_ec_cfp, get_iseq_encoded_size, imemo_iseq, rb_IMEMO_TYPE_P,
        rb_iseq_pc_at_idx, EcPtr, IseqPtr, RUBY_OFFSET_CFP_JIT_RETURN, RUBY_OFFSET_CFP_SP,
    },
    dev::options::get_option_ref,
    dev::stats::incr_counter,
    iseq::get_or_create_iseq_payload,
    meta::block::{BlockId, BlockRef, BranchTarget},
    meta::context::Context,
    remove_block::free_block,
    utils::iseq_get_location,
    virtualmem::CodePtr,
};

use crate::cruby::get_iseq_flags_has_opt;

use std::mem;

#[cfg(feature = "disasm")]
use crate::dev::disasm::disasm_iseq_insn_range;

/// See [gen_block_series_body]. This simply counts compilation failures.
pub fn gen_block_series(
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

    let mut code_generator = CodeGenerator::init(blockid, start_ctx, cb, ec);

    // Generate code for the first block
    let first_block = code_generator
        .gen_single_block(blockid, start_ctx, ec, cb)
        .ok()?;
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

        let mut code_generator = CodeGenerator::init(requested_blockid, &requested_ctx, cb, ec);

        // Generate new block using context from the last branch.
        let result = code_generator.gen_single_block(requested_blockid, &requested_ctx, ec, cb);

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

/// Compile an interpreter entry block to be inserted into an iseq
/// Returns None if compilation fails.
pub fn gen_entry_prologue(cb: &mut CodeBlock, iseq: IseqPtr, insn_idx: u32) -> Option<CodePtr> {
    let code_ptr = cb.get_write_ptr();

    let mut asm = Assembler::new();
    if get_option_ref!(dump_disasm).is_some() {
        asm.comment(&format!("YJIT entry point: {}", iseq_get_location(iseq, 0)));
    } else {
        asm.comment("YJIT entry");
    }

    asm.frame_setup();

    // Save the CFP, EC, SP registers to the C stack
    asm.cpush(CFP);
    asm.cpush(EC);
    asm.cpush(SP);

    // We are passed EC and CFP as arguments
    asm.mov(EC, C_ARG_OPNDS[0]);
    asm.mov(CFP, C_ARG_OPNDS[1]);

    // Load the current SP from the CFP into REG_SP
    asm.mov(SP, Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SP));

    // Setup cfp->jit_return
    asm.mov(
        Opnd::mem(64, CFP, RUBY_OFFSET_CFP_JIT_RETURN),
        Opnd::const_ptr(CodegenGlobals::get_leave_exit_code().raw_ptr()),
    );

    // We're compiling iseqs that we *expect* to start at `insn_idx`. But in
    // the case of optional parameters, the interpreter can set the pc to a
    // different location depending on the optional parameters.  If an iseq
    // has optional parameters, we'll add a runtime check that the PC we've
    // compiled for is the same PC that the interpreter wants us to run with.
    // If they don't match, then we'll take a side exit.
    if unsafe { get_iseq_flags_has_opt(iseq) } {
        old_gen_pc_guard(&mut asm, iseq, insn_idx);
    }

    asm.compile(cb);

    if cb.has_dropped_bytes() {
        None
    } else {
        // Mark code pages for code GC
        let iseq_payload = get_or_create_iseq_payload(iseq);
        for page in cb.addrs_to_pages(code_ptr, cb.get_write_ptr()) {
            iseq_payload.pages.insert(page);
        }
        Some(code_ptr)
    }
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

// Some runtime checks for integrity of a program location
pub fn verify_blockid(blockid: BlockId) {
    unsafe {
        assert!(rb_IMEMO_TYPE_P(blockid.iseq.into(), imemo_iseq) != 0);
        assert!(blockid.idx < get_iseq_encoded_size(blockid.iseq));
    }
}

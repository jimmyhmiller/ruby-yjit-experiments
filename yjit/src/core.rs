use crate::{
    asm::CodeBlock,
    bbv::{add_block_version, remove_block_version},
    codegen::generator::CodeGenerator,
    cruby::{get_iseq_encoded_size, imemo_iseq, rb_IMEMO_TYPE_P, EcPtr},
    dev::stats::incr_counter,
    meta::block::{BlockId, BlockRef, BranchTarget},
    meta::context::Context,
    remove_block::free_block,
};

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

    debug_print_compiling(blockid, last_blockref, batch);

    Some(first_block)
}

#[cfg(feature = "disasm")]
fn debug_print_compiling(blockid: BlockId, last_blockref: BlockRef, batch: Vec<BlockRef>) {
    use crate::dev::options::get_option_ref;
    use crate::utils::iseq_get_location;
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
#[cfg(not(feature = "disasm"))]
fn debug_print_compiling(_blockid: BlockId, _last_blockref: BlockRef, _batch: Vec<BlockRef>) {}

// Some runtime checks for integrity of a program location
pub fn verify_blockid(blockid: BlockId) {
    unsafe {
        assert!(rb_IMEMO_TYPE_P(blockid.iseq.into(), imemo_iseq) != 0);
        assert!(blockid.idx < get_iseq_encoded_size(blockid.iseq));
    }
}

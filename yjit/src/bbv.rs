use crate::{
    asm::CodeBlock,
    cruby::{obj_written, IseqPtr, VALUE},
    dev::{options::get_option, stats::incr_counter},
    iseq::{get_iseq_payload, get_or_create_iseq_payload},
    meta::{
        block::{BlockId, BlockRef, VersionList},
        context::{Context, TypeDiff},
    },
    utils::IntoUsize,
};

use std::mem;

/// Get all blocks for a particular place in an iseq.
pub fn get_version_list(blockid: BlockId) -> Option<&'static mut VersionList> {
    let insn_idx = blockid.idx.into_usize();
    match get_iseq_payload(blockid.iseq) {
        Some(payload) if insn_idx < payload.version_map.len() => {
            Some(payload.version_map.get_mut(insn_idx).unwrap())
        }
        _ => None,
    }
}

/// Get or create all blocks for a particular place in an iseq.
pub fn get_or_create_version_list(blockid: BlockId) -> &'static mut VersionList {
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
pub fn get_num_versions(blockid: BlockId) -> usize {
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
pub fn find_block_version(blockid: BlockId, ctx: &Context) -> Option<BlockRef> {
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
pub fn add_block_version(blockref: &BlockRef, cb: &CodeBlock) {
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
pub fn remove_block_version(blockref: &BlockRef) {
    let block = blockref.borrow();
    let version_list = match get_version_list(block.blockid) {
        Some(version_list) => version_list,
        None => return,
    };

    // Retain the versions that are not this one
    version_list.retain(|other| blockref != other);
}

use crate::{
    asm::CodeBlock,
    backend::ir::{Assembler, Opnd, CFP, C_ARG_OPNDS, EC, SP},
    codegen::{globals::CodegenGlobals, old_gen_pc_guard, CodePtr},
    core::gen_block_series,
    cruby::{
        get_cfp_pc, get_ec_cfp, get_iseq_flags_has_opt, rb_iseq_pc_at_idx, EcPtr, IseqPtr,
        RUBY_OFFSET_CFP_JIT_RETURN, RUBY_OFFSET_CFP_SP,
    },
    dev::options::get_option_ref,
    iseq::get_or_create_iseq_payload,
    meta::{block::BlockId, context::Context},
    utils::iseq_get_location,
};

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

    // TODO: Not a fan of this call being here. I think

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

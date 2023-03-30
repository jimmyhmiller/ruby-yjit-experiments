// We use the YARV bytecode constants which have a CRuby-style name
#![allow(non_upper_case_globals)]

use std::os::raw::{c_int, c_uint};
use std::ptr;
use std::slice;

use crate::bbv::limit_block_versions;
use crate::iseq::get_or_create_iseq_payload;
use crate::meta::context::{verify_ctx, YARVOpnd};
pub use crate::virtualmem::CodePtr;
use crate::{
    asm::{CodeBlock, OutlinedCb},
    backend::ir::{Assembler, Opnd, Target, CFP, C_ARG_OPNDS, C_RET_OPND, EC, SP},
    codegen::globals::CodegenGlobals,
    core::{
        free_block, gen_branch, gen_direct_jump, make_branch_entry, set_branch_target,
        verify_blockid,
    },
    counted_exit,
    // Intentionally expanding all of these so we can see all the stuff we depend on.
    // To me this signals a potential missing abstraction
    cruby::{
        block_type_iseq, get_call_data_ci, get_cfp_ep, get_cikw_keyword_len, get_cikw_keywords_idx,
        get_cme_def_body_attr_id, get_cme_def_body_cfunc, get_cme_def_body_optimized_index,
        get_cme_def_body_optimized_type, get_cme_def_type, get_def_iseq_ptr, get_def_method_serial,
        get_def_original_id, get_ec_cfp, get_iseq_body_local_iseq, get_iseq_body_local_table_size,
        get_iseq_body_param_keyword, get_iseq_body_param_lead_num, get_iseq_body_param_opt_num,
        get_iseq_body_param_opt_table, get_iseq_body_param_size, get_iseq_body_stack_max,
        get_iseq_encoded_size, get_iseq_flags_accepts_no_kwarg, get_iseq_flags_ambiguous_param0,
        get_iseq_flags_has_block, get_iseq_flags_has_kw, get_iseq_flags_has_kwrest,
        get_iseq_flags_has_lead, get_iseq_flags_has_opt, get_iseq_flags_has_post,
        get_iseq_flags_has_rest, get_iseq_flags_ruby2_keywords, get_mct_argc, get_mct_func,
        imemo_callinfo, insn_len, insn_name, iseq_inline_constant_cache, rb_IMEMO_TYPE_P,
        rb_aliased_callable_method_entry, rb_ary_clear, rb_ary_entry_internal, rb_ary_resurrect,
        rb_ary_store, rb_ary_tmp_new_from_values, rb_backref_get, rb_block_param_proxy,
        rb_builtin_function, rb_cArray, rb_cFalseClass, rb_cFloat, rb_cHash, rb_cInteger,
        rb_cNilClass, rb_cString, rb_cSymbol, rb_cTrueClass, rb_c_method_tracing_currently_enabled,
        rb_call_data, rb_callable_method_entry, rb_callable_method_entry_t, rb_callinfo,
        rb_captured_block, rb_class_allocate_instance, rb_class_attached_object,
        rb_class_get_superclass, rb_ec_ary_new_from_values, rb_ec_str_resurrect,
        rb_ensure_iv_list_size, rb_execution_context_struct, rb_fix_mod_fix, rb_full_cfunc_return,
        rb_gc_writebarrier, rb_get_alloc_func, rb_get_def_bmethod_proc,
        rb_get_iseq_body_local_iseq, rb_get_iseq_body_param_lead_num, rb_get_iseq_body_parent_iseq,
        rb_get_symbol_id, rb_gvar_get, rb_gvar_set, rb_hash_aref, rb_hash_aset,
        rb_hash_bulk_insert, rb_hash_new, rb_hash_new_with_size, rb_hash_resurrect,
        rb_hash_stlike_foreach, rb_hash_stlike_lookup, rb_iseq_opcode_at_pc, rb_iseq_pc_at_idx,
        rb_iseq_t, rb_ivar_get, rb_leaf_builtin_function, rb_mRubyVMFrozenCore,
        rb_method_definition_t, rb_obj_as_string_result, rb_obj_is_kind_of, rb_optimized_call,
        rb_range_new, rb_reg_last_match, rb_reg_match_last, rb_reg_match_post, rb_reg_match_pre,
        rb_reg_new_ary, rb_reg_nth_match, rb_shape_get_iv_index, rb_shape_get_next,
        rb_shape_get_shape_by_id, rb_shape_get_shape_id, rb_shape_id, rb_shape_id_offset,
        rb_shape_transition_shape_capa, rb_str_concat_literals, rb_str_eql_internal, rb_str_intern,
        rb_str_neq_internal, rb_sym2id, rb_vm_bh_to_procval, rb_vm_concat_array, rb_vm_defined,
        rb_vm_ep_local_ep, rb_vm_frame_method_entry, rb_vm_getclassvariable, rb_vm_ic_hit_p,
        rb_vm_set_ivar_id, rb_vm_setclassvariable, rb_vm_setinstancevariable, rb_vm_splat_array,
        rb_yjit_array_len, rb_yjit_get_proc_ptr, ruby_basic_operators, st_data_t, vm_ci_argc,
        vm_ci_kwarg, vm_ci_mid, EcPtr, IseqPtr, Qfalse, Qnil, Qtrue, Qundef, RBasic,
        RedefinitionFlag, YARVINSN_opt_getconstant_path, YARVINSN_putobject_INT2FIX_0_,
        ARRAY_REDEFINED_OP_FLAG, BASIC_OP_UNREDEFINED_P, BOP_AND, BOP_AREF, BOP_EQ, BOP_EQQ,
        BOP_FREEZE, BOP_GE, BOP_GT, BOP_LE, BOP_LT, BOP_MINUS, BOP_MOD, BOP_OR, BOP_PLUS,
        BOP_UMINUS, FL_TEST, FL_TEST_RAW, HASH_REDEFINED_OP_FLAG, ID, INTEGER_REDEFINED_OP_FLAG,
        METHOD_ENTRY_VISI, METHOD_VISI_PRIVATE, METHOD_VISI_PROTECTED, METHOD_VISI_PUBLIC,
        OBJ_TOO_COMPLEX_SHAPE_ID, OPTIMIZED_METHOD_TYPE_BLOCK_CALL, OPTIMIZED_METHOD_TYPE_CALL,
        OPTIMIZED_METHOD_TYPE_SEND, OPTIMIZED_METHOD_TYPE_STRUCT_AREF,
        OPTIMIZED_METHOD_TYPE_STRUCT_ASET, RARRAY_EMBED_FLAG, RARRAY_EMBED_LEN_MASK,
        RARRAY_EMBED_LEN_SHIFT, RB_TYPE_P, RCLASS_ORIGIN, RHASH_PASS_AS_KEYWORDS,
        RMODULE_IS_REFINEMENT, ROBJECT_EMBED, ROBJECT_OFFSET_AS_ARY, ROBJECT_OFFSET_AS_HEAP_IVPTR,
        RSTRUCT_EMBED_LEN_MASK, RSTRUCT_LEN, RSTRUCT_SET, RUBY_FIXNUM_FLAG, RUBY_FLONUM_FLAG,
        RUBY_FLONUM_MASK, RUBY_FL_SINGLETON, RUBY_IMMEDIATE_MASK, RUBY_OFFSET_CFP_BLOCK_CODE,
        RUBY_OFFSET_CFP_BP, RUBY_OFFSET_CFP_EP, RUBY_OFFSET_CFP_ISEQ, RUBY_OFFSET_CFP_JIT_RETURN,
        RUBY_OFFSET_CFP_PC, RUBY_OFFSET_CFP_SELF, RUBY_OFFSET_CFP_SP, RUBY_OFFSET_EC_CFP,
        RUBY_OFFSET_EC_INTERRUPT_FLAG, RUBY_OFFSET_ICE_VALUE, RUBY_OFFSET_IC_ENTRY,
        RUBY_OFFSET_RARRAY_AS_ARY, RUBY_OFFSET_RARRAY_AS_HEAP_LEN, RUBY_OFFSET_RARRAY_AS_HEAP_PTR,
        RUBY_OFFSET_RBASIC_FLAGS, RUBY_OFFSET_RBASIC_KLASS, RUBY_OFFSET_RSTRUCT_AS_ARY,
        RUBY_OFFSET_RSTRUCT_AS_HEAP_PTR, RUBY_SIZEOF_CONTROL_FRAME, RUBY_SPECIAL_SHIFT,
        RUBY_SYMBOL_FLAG, RUBY_T_ARRAY, RUBY_T_HASH, RUBY_T_ICLASS, RUBY_T_MASK, RUBY_T_MODULE,
        RUBY_T_OBJECT, RUBY_T_STRING, RUBY_T_STRUCT, SHAPE_ID_NUM_BITS, SIZEOF_VALUE,
        SIZEOF_VALUE_I32, STRING_REDEFINED_OP_FLAG, ST_CONTINUE, ST_STOP, VALUE, VALUE_BITS,
        VM_BLOCK_HANDLER_NONE, VM_CALL_FCALL, VM_CALL_KW_SPLAT, VM_CALL_OPT_SEND,
        VM_ENV_DATA_INDEX_FLAGS, VM_ENV_DATA_INDEX_ME_CREF, VM_ENV_DATA_INDEX_SPECVAL,
        VM_ENV_DATA_SIZE, VM_ENV_FLAG_LOCAL, VM_ENV_FLAG_WB_REQUIRED, VM_FRAME_FLAG_BMETHOD,
        VM_FRAME_FLAG_CFRAME, VM_FRAME_FLAG_CFRAME_KW, VM_FRAME_FLAG_LAMBDA,
        VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM, VM_FRAME_MAGIC_BLOCK, VM_FRAME_MAGIC_CFUNC,
        VM_FRAME_MAGIC_METHOD, VM_METHOD_TYPE_ALIAS, VM_METHOD_TYPE_ATTRSET,
        VM_METHOD_TYPE_BMETHOD, VM_METHOD_TYPE_CFUNC, VM_METHOD_TYPE_ISEQ, VM_METHOD_TYPE_IVAR,
        VM_METHOD_TYPE_MISSING, VM_METHOD_TYPE_NOTIMPLEMENTED, VM_METHOD_TYPE_OPTIMIZED,
        VM_METHOD_TYPE_REFINED, VM_METHOD_TYPE_UNDEF, VM_METHOD_TYPE_ZSUPER,
        VM_SPECIAL_OBJECT_VMCORE,
    },
    dev::options::{get_option, get_option_ref},
    dev::stats::{
        incr_counter, ptr_to_counter, rb_yjit_count_side_exit_op, rb_yjit_record_exit_stack,
    },
    gen_counter_incr,
    meta::block::{Block, BlockId, BlockRef, BranchGenFn, BranchShape},
    meta::call_info::CallInfo,
    meta::context::{Context, Type, TypeDiff},
    meta::invariants::{
        assume_method_lookup_stable, assume_single_ractor_mode, assume_stable_constant_names,
        Invariants,
    },
    meta::jit_state::JITState,
    utils::{iseq_get_location, print_str, IntoUsize},
};

pub mod globals;
pub mod method_overrides;

/// Status returned by code generation functions
#[derive(PartialEq, Debug)]
enum CodegenStatus {
    KeepCompiling,
    CantCompile,
    EndBlock,
}

/// Code generation function signature
type InsnGenFn = fn(code_generator: &mut CodeGenerator) -> CodegenStatus;

use crate::codegen::JCCKinds::*;

#[allow(non_camel_case_types, unused)]
pub enum JCCKinds {
    JCC_JNE,
    JCC_JNZ,
    JCC_JZ,
    JCC_JE,
    JCC_JBE,
    JCC_JNA,
}

// Save the incremented PC on the CFP
// This is necessary when callees can raise or allocate
fn jit_save_pc(jit: &JITState, asm: &mut Assembler) {
    let pc: *mut VALUE = jit.get_pc();
    let ptr: *mut VALUE = unsafe {
        let cur_insn_len = insn_len(jit.get_opcode()) as isize;
        pc.offset(cur_insn_len)
    };

    asm.comment("save PC to CFP");
    asm.mov(
        Opnd::mem(64, CFP, RUBY_OFFSET_CFP_PC),
        Opnd::const_ptr(ptr as *const u8),
    );
}

/// Save the current SP on the CFP
/// This realigns the interpreter SP with the JIT SP
/// Note: this will change the current value of REG_SP,
///       which could invalidate memory operands
fn gen_save_sp(asm: &mut Assembler, ctx: &mut Context) {
    if ctx.get_sp_offset() != 0 {
        asm.comment("save SP to CFP");
        let stack_pointer = ctx.sp_opnd(0);
        let sp_addr = asm.lea(stack_pointer);
        asm.mov(SP, sp_addr);
        let cfp_sp_opnd = Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SP);
        asm.mov(cfp_sp_opnd, SP);
        ctx.set_sp_offset(0);
    }
}

/// Record the current codeblock write position for rewriting into a jump into
/// the outlined block later. Used to implement global code invalidation.
fn record_global_inval_patch(asm: &mut Assembler, outline_block_target_pos: CodePtr) {
    asm.pad_inval_patch();
    asm.pos_marker(move |code_ptr| {
        CodegenGlobals::push_global_inval_patch(code_ptr, outline_block_target_pos);
    });
}

// Fill code_for_exit_from_stub. This is used by branch_stub_hit() to exit
// to the interpreter when it cannot service a stub by generating new code.
// Before coming here, branch_stub_hit() takes care of fully reconstructing
// interpreter state.
fn gen_code_for_exit_from_stub(ocb: &mut OutlinedCb) -> CodePtr {
    let ocb = ocb.unwrap();
    let code_ptr = ocb.get_write_ptr();
    let mut asm = Assembler::new();

    gen_counter_incr!(&mut asm, exit_from_branch_stub);

    asm.comment("exit from branch stub");
    asm.cpop_into(SP);
    asm.cpop_into(EC);
    asm.cpop_into(CFP);

    asm.frame_teardown();

    asm.cret(Qundef.into());

    asm.compile(ocb);

    code_ptr
}

/// Generate an exit to return to the interpreter
fn gen_exit(exit_pc: *mut VALUE, ctx: &Context, asm: &mut Assembler) {
    #[cfg(all(feature = "disasm", not(test)))]
    {
        use crate::cruby::rb_vm_insn_addr2opcode;
        let opcode = unsafe { rb_vm_insn_addr2opcode((*exit_pc).as_ptr()) };
        asm.comment(&format!(
            "exit to interpreter on {}",
            insn_name(opcode as usize)
        ));
    }

    // Generate the code to exit to the interpreters
    // Write the adjusted SP back into the CFP
    if ctx.get_sp_offset() != 0 {
        let sp_opnd = asm.lea(ctx.sp_opnd(0));
        asm.mov(Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SP), sp_opnd);
    }

    // Update CFP->PC
    asm.mov(
        Opnd::mem(64, CFP, RUBY_OFFSET_CFP_PC),
        Opnd::const_ptr(exit_pc as *const u8),
    );

    // Accumulate stats about interpreter exits
    if get_option!(gen_stats) {
        asm.ccall(
            rb_yjit_count_side_exit_op as *const u8,
            vec![Opnd::const_ptr(exit_pc as *const u8)],
        );

        // If --yjit-trace-exits option is enabled, record the exit stack
        // while recording the side exits.
        if get_option!(gen_trace_exits) {
            asm.ccall(
                rb_yjit_record_exit_stack as *const u8,
                vec![Opnd::const_ptr(exit_pc as *const u8)],
            );
        }
    }

    asm.cpop_into(SP);
    asm.cpop_into(EC);
    asm.cpop_into(CFP);

    asm.frame_teardown();

    asm.cret(Qundef.into());
}

/// Generate an exit to the interpreter in the outlined code block
fn gen_outlined_exit(exit_pc: *mut VALUE, ctx: &Context, ocb: &mut OutlinedCb) -> CodePtr {
    let cb = ocb.unwrap();
    let exit_code = cb.get_write_ptr();
    let mut asm = Assembler::new();

    gen_exit(exit_pc, ctx, &mut asm);

    asm.compile(cb);

    exit_code
}

// Landing code for when c_return tracing is enabled. See full_cfunc_return().
fn gen_full_cfunc_return(ocb: &mut OutlinedCb) -> CodePtr {
    let ocb = ocb.unwrap();
    let code_ptr = ocb.get_write_ptr();
    let mut asm = Assembler::new();

    // This chunk of code expects REG_EC to be filled properly and
    // RAX to contain the return value of the C method.

    asm.comment("full cfunc return");
    asm.ccall(rb_full_cfunc_return as *const u8, vec![EC, C_RET_OPND]);

    // Count the exit
    gen_counter_incr!(asm, traced_cfunc_return);

    // Return to the interpreter
    asm.cpop_into(SP);
    asm.cpop_into(EC);
    asm.cpop_into(CFP);

    asm.frame_teardown();

    asm.cret(Qundef.into());

    asm.compile(ocb);

    code_ptr
}

/// Generate a continuation for leave that exits to the interpreter at REG_CFP->pc.
/// This is used by gen_leave() and gen_entry_prologue()
fn gen_leave_exit(ocb: &mut OutlinedCb) -> CodePtr {
    let ocb = ocb.unwrap();
    let code_ptr = ocb.get_write_ptr();
    let mut asm = Assembler::new();

    // gen_leave() fully reconstructs interpreter state and leaves the
    // return value in C_RET_OPND before coming here.
    let ret_opnd = asm.live_reg_opnd(C_RET_OPND);

    // Every exit to the interpreter should be counted
    gen_counter_incr!(asm, leave_interp_return);

    asm.comment("exit from leave");
    asm.cpop_into(SP);
    asm.cpop_into(EC);
    asm.cpop_into(CFP);

    asm.frame_teardown();

    asm.cret(ret_opnd);

    asm.compile(ocb);

    code_ptr
}

// Generate a runtime guard that ensures the PC is at the expected
// instruction index in the iseq, otherwise takes a side-exit.
// This is to handle the situation of optional parameters.
// When a function with optional parameters is called, the entry
// PC for the method isn't necessarily 0.
fn gen_pc_guard(asm: &mut Assembler, iseq: IseqPtr, insn_idx: u32) {
    let pc_opnd = Opnd::mem(64, CFP, RUBY_OFFSET_CFP_PC);
    let expected_pc = unsafe { rb_iseq_pc_at_idx(iseq, insn_idx) };
    let expected_pc_opnd = Opnd::const_ptr(expected_pc as *const u8);

    asm.cmp(pc_opnd, expected_pc_opnd);

    let pc_match = asm.new_label("pc_match");
    asm.je(pc_match);

    // We're not starting at the first PC, so we need to exit.
    gen_counter_incr!(asm, leave_start_pc_non_zero);

    asm.cpop_into(SP);
    asm.cpop_into(EC);
    asm.cpop_into(CFP);

    asm.frame_teardown();

    asm.cret(Qundef.into());

    // PC should match the expected insn_idx
    asm.write_label(pc_match);
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
        gen_pc_guard(&mut asm, iseq, insn_idx);
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

// Generate code to check for interrupts and take a side-exit.
// Warning: this function clobbers REG0
fn gen_check_ints(asm: &mut Assembler, side_exit: Target) {
    // Check for interrupts
    // see RUBY_VM_CHECK_INTS(ec) macro
    asm.comment("RUBY_VM_CHECK_INTS(ec)");

    // Not checking interrupt_mask since it's zero outside finalize_deferred_heap_pages,
    // signal_exec, or rb_postponed_job_flush.
    let interrupt_flag = asm.load(Opnd::mem(32, EC, RUBY_OFFSET_EC_INTERRUPT_FLAG));
    asm.test(interrupt_flag, interrupt_flag);

    asm.jnz(side_exit);
}

// Compile a sequence of bytecode instructions for a given basic block version.
// Part of gen_block_version().
// Note: this function will mutate its context while generating code,
//       but the input start_ctx argument should remain immutable.
pub fn gen_single_block(
    blockid: BlockId,
    start_ctx: &Context,
    ec: EcPtr,
    cb: &mut CodeBlock,
) -> Result<BlockRef, ()> {
    // Limit the number of specialized versions for this block
    let ctx = limit_block_versions(blockid, start_ctx);

    verify_blockid(blockid);
    assert!(!(blockid.idx == 0 && ctx.get_stack_size() > 0));

    // Instruction sequence to compile
    let iseq = blockid.iseq;
    let iseq_size = unsafe { get_iseq_encoded_size(iseq) };
    let mut insn_idx: c_uint = blockid.idx;
    let starting_insn_idx = insn_idx;

    // Allocate the new block
    let blockref = Block::make_ref(blockid, &ctx, cb.get_write_ptr());

    // Initialize a JIT state object
    let mut jit = JITState::new(&blockref);
    jit.iseq = blockid.iseq;
    jit.ec = Some(ec);

    // Create a backend assembler instance
    let asm = Assembler::new();

    let mut code_generator =
        CodeGenerator::new(jit, ctx, asm, CodegenGlobals::take_outlined_cb().unwrap());

    #[cfg(feature = "disasm")]
    if get_option_ref!(dump_disasm).is_some() {
        let blockid_idx = blockid.idx;
        let chain_depth = if code_generator.ctx.get_chain_depth() > 0 {
            format!(", chain_depth: {}", code_generator.ctx.get_chain_depth())
        } else {
            "".to_string()
        };
        code_generator.asm.comment(&format!(
            "Block: {} (ISEQ offset: {}{})",
            iseq_get_location(blockid.iseq, blockid_idx),
            blockid_idx,
            chain_depth
        ));
    }

    // For each instruction to compile
    // NOTE: could rewrite this loop with a std::iter::Iterator
    while insn_idx < iseq_size {
        let starting_ctx = code_generator.ctx.clone();
        // Get the current pc and opcode
        let pc = unsafe { rb_iseq_pc_at_idx(iseq, insn_idx) };
        // try_into() call below is unfortunate. Maybe pick i32 instead of usize for opcodes.
        let opcode: usize = unsafe { rb_iseq_opcode_at_pc(iseq, pc) }
            .try_into()
            .unwrap();

        // We need opt_getconstant_path to be in a block all on its own. Cut the block short
        // if we run into it. This is necessary because we want to invalidate based on the
        // instruction's index.
        if opcode == YARVINSN_opt_getconstant_path.into_usize() && insn_idx > starting_insn_idx {
            // TODO: JIMMY Need a code generator
            code_generator.jump_to_next_insn();
            break;
        }

        // Set the current instruction
        code_generator.jit.insn_idx = insn_idx;
        code_generator.jit.opcode = opcode;
        code_generator.jit.pc = pc;
        code_generator.jit.side_exit_for_pc = None;

        // If previous instruction requested to record the boundary
        if code_generator.jit.record_boundary_patch_point {
            // Generate an exit to this instruction and record it
            let exit_pos = gen_outlined_exit(
                code_generator.jit.pc,
                &code_generator.ctx,
                &mut code_generator.ocb,
            );
            record_global_inval_patch(&mut code_generator.asm, exit_pos);
            code_generator.jit.record_boundary_patch_point = false;
        }

        // In debug mode, verify our existing assumption
        if cfg!(debug_assertions) && get_option!(verify_ctx) && code_generator.jit.at_current_insn()
        {
            verify_ctx(&code_generator.jit, &code_generator.ctx);
        }

        // Lookup the codegen function for this instruction
        let mut status = CodegenStatus::CantCompile;
        if let Some(gen_fn) = get_gen_fn(VALUE(opcode)) {
            // :count-placement:
            // Count bytecode instructions that execute in generated code.
            // Note that the increment happens even when the output takes side exit.
            gen_counter_incr!(code_generator.asm, exec_instruction);

            // Add a comment for the name of the YARV instruction
            code_generator
                .asm
                .comment(&format!("Insn: {}", insn_name(opcode)));

            // If requested, dump instructions for debugging
            if get_option!(dump_insns) {
                println!("compiling {}", insn_name(opcode));
                print_str(
                    &mut code_generator.asm,
                    &format!("executing {}", insn_name(opcode)),
                );
            }

            // Call the code generation function
            status = gen_fn(&mut code_generator);
        }

        // If we can't compile this instruction
        // exit to the interpreter and stop compiling
        if status == CodegenStatus::CantCompile {
            if get_option!(dump_insns) {
                println!("can't compile {}", insn_name(opcode));
            }

            let mut block = code_generator.jit.block.borrow_mut();

            // We are using starting_ctx so that if code_generator.ctx got mutated
            // it won't matter. If you write to the stack to you could still get errors,
            // but not from simple push and pops
            gen_exit(
                code_generator.jit.pc,
                &starting_ctx,
                &mut code_generator.asm,
            );

            // If this is the first instruction in the block, then we can use
            // the exit for block->entry_exit.
            if insn_idx == block.get_blockid().idx {
                block.entry_exit = Some(block.get_start_addr());
            }

            break;
        }

        // For now, reset the chain depth after each instruction as only the
        // first instruction in the block can concern itself with the depth.
        code_generator.ctx.reset_chain_depth();

        // Move to the next instruction to compile
        insn_idx += insn_len(opcode);

        // If the instruction terminates this block
        if status == CodegenStatus::EndBlock {
            break;
        }
    }

    // Finish filling out the block
    {
        CodegenGlobals::set_outlined_cb(code_generator.ocb);
        let mut block = code_generator.jit.block.borrow_mut();
        if block.entry_exit.is_some() {
            code_generator.asm.pad_inval_patch();
        }

        // Compile code into the code block
        let gc_offsets = code_generator.asm.compile(cb);

        // Add the GC offsets to the block
        block.set_gc_obj_offsets(gc_offsets);

        // Set CME dependencies to the block
        block.set_cme_dependencies(code_generator.jit.cme_dependencies);

        // Set outgoing branches to the block
        block.set_outgoing(code_generator.jit.outgoing);

        // Mark the end position of the block
        block.set_end_addr(cb.get_write_ptr());

        // Store the index of the last instruction in the block
        block.set_end_idx(insn_idx);
    }

    // We currently can't handle cases where the request is for a block that
    // doesn't go to the next instruction.
    assert!(!code_generator.jit.record_boundary_patch_point);

    let ocb_dropped_bytes =
        CodegenGlobals::map_outlined_cb(|ocb| ocb.unwrap().has_dropped_bytes()).unwrap();
    // If code for the block doesn't fit, fail
    if cb.has_dropped_bytes() || ocb_dropped_bytes {
        free_block(&blockref);
        return Err(());
    }

    // Block compiled successfully
    Ok(blockref)
}

pub struct CodeGenerator {
    pub jit: JITState,
    pub ctx: Context,
    pub asm: Assembler,
    pub ocb: OutlinedCb,
}

impl CodeGenerator {
    pub fn new(jit: JITState, ctx: Context, asm: Assembler, ocb: OutlinedCb) -> Self {
        Self { jit, ctx, asm, ocb }
    }

    pub fn get_ocb(&mut self) -> &mut OutlinedCb {
        &mut self.ocb
    }

    /// A public function that can be called from within the code generation
    /// functions to ensure that the block being generated is invalidated when the
    /// basic operator is redefined.
    pub fn assume_bop_not_redefined(
        &mut self,
        klass: RedefinitionFlag,
        bop: ruby_basic_operators,
    ) -> bool {
        if unsafe { BASIC_OP_UNREDEFINED_P(bop, klass) } {
            self.jit_ensure_block_entry_exit();

            let invariants = Invariants::get_instance();
            invariants
                .basic_operator_blocks
                .entry((klass, bop))
                .or_default()
                .insert(self.jit.get_block());
            invariants
                .block_basic_operators
                .entry(self.jit.get_block())
                .or_default()
                .insert((klass, bop));

            true
        } else {
            false
        }
    }

    // Generate a stubbed unconditional jump to the next bytecode instruction.
    // Blocks that are part of a guard chain can use this to share the same successor.
    fn jump_to_next_insn(&mut self) {
        // Reset the depth since in current usages we only ever jump to to
        // chain_depth > 0 from the same instruction.
        let mut reset_depth = self.ctx.clone();
        reset_depth.reset_chain_depth();

        let jump_block = BlockId {
            iseq: self.jit.iseq,
            idx: self.jit.next_insn_idx(),
        };

        // We are at the end of the current instruction. Record the boundary.
        if self.jit.record_boundary_patch_point {
            let exit_pc = unsafe {
                self.jit
                    .pc
                    .offset(insn_len(self.jit.opcode).try_into().unwrap())
            };
            let exit_pos = gen_outlined_exit(exit_pc, &reset_depth, self.get_ocb());
            record_global_inval_patch(&mut self.asm, exit_pos);
            self.jit.record_boundary_patch_point = false;
        }

        // Generate the jump instruction
        gen_direct_jump(&mut self.jit, &reset_depth, jump_block, &mut self.asm);
    }

    // Ensure that there is an exit for the start of the block being compiled.
    // Block invalidation uses this exit.
    pub fn jit_ensure_block_entry_exit(&mut self) {
        let blockref = self.jit.block.clone();
        let mut block = blockref.borrow_mut();
        let block_ctx = block.get_ctx();
        let blockid = block.get_blockid();

        if block.entry_exit.is_some() {
            return;
        }

        // If we're compiling the first instruction in the block.
        if self.jit.insn_idx == blockid.idx {
            // Generate the exit with the cache in jitstate.
            block.entry_exit = Some(self.get_side_exit(&block_ctx).unwrap_code_ptr());
        } else {
            let block_entry_pc = unsafe { rb_iseq_pc_at_idx(blockid.iseq, blockid.idx) };
            block.entry_exit = Some(gen_outlined_exit(
                block_entry_pc,
                &block_ctx,
                self.get_ocb(),
            ));
        }
    }

    // Generate RARRAY_LEN. For array_opnd, use Opnd::Reg to reduce memory access,
    // and use Opnd::Mem to save registers.
    fn get_array_len(&mut self, array_opnd: Opnd) -> Opnd {
        self.asm.comment("get array length for embedded or heap");

        // Pull out the embed flag to check if it's an embedded array.
        let array_reg = match array_opnd {
            Opnd::Reg(_) => array_opnd,
            _ => self.asm.load(array_opnd),
        };
        let flags_opnd = Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RBASIC_FLAGS);

        // Get the length of the array
        let emb_len_opnd = self
            .asm
            .and(flags_opnd, (RARRAY_EMBED_LEN_MASK as u64).into());
        let emb_len_opnd = self
            .asm
            .rshift(emb_len_opnd, (RARRAY_EMBED_LEN_SHIFT as u64).into());

        // Conditionally move the length of the heap array
        let flags_opnd = Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RBASIC_FLAGS);
        self.asm.test(flags_opnd, (RARRAY_EMBED_FLAG as u64).into());

        let array_reg = match array_opnd {
            Opnd::Reg(_) => array_opnd,
            _ => self.asm.load(array_opnd),
        };
        let array_len_opnd = Opnd::mem(
            std::os::raw::c_long::BITS as u8,
            array_reg,
            RUBY_OFFSET_RARRAY_AS_HEAP_LEN,
        );

        // Select the array length value
        self.asm.csel_nz(emb_len_opnd, array_len_opnd)
    }

    /// Create a stub to force the code up to this point to be executed
    pub fn defer_compilation(&mut self) {
        if self.ctx.chain_depth != 0 {
            panic!("Double defer!");
        }

        let mut next_ctx = self.ctx.clone();

        if next_ctx.chain_depth == u8::MAX {
            panic!("max block version chain depth reached!");
        }
        next_ctx.chain_depth += 1;

        let block_rc = self.jit.get_block();
        let branch_rc = make_branch_entry(
            &mut self.jit,
            &block_rc,
            BranchGenFn::JumpToTarget0(BranchShape::Default),
        );
        let mut branch = branch_rc.borrow_mut();
        let block = block_rc.borrow();

        let blockid = BlockId {
            iseq: block.blockid.iseq,
            idx: self.jit.get_insn_idx(),
        };
        set_branch_target(
            0,
            blockid,
            &next_ctx,
            &branch_rc,
            &mut branch,
            self.get_ocb(),
        );

        // Call the branch generation function
        self.asm.comment("defer_compilation");
        self.asm.mark_branch_start(&branch_rc);
        if let Some(dst_addr) = branch.get_target_address(0) {
            branch.gen_fn.call(&mut self.asm, dst_addr, None);
        }
        self.asm.mark_branch_end(&branch_rc);

        // If the block we're deferring from is empty
        if self.jit.get_block().borrow().get_blockid().idx == self.jit.get_insn_idx() {
            incr_counter!(defer_empty_count);
        }

        incr_counter!(defer_count);
    }

    fn gen_nop(&mut self) -> CodegenStatus {
        // Do nothing
        CodegenStatus::KeepCompiling
    }

    fn gen_pop(&mut self) -> CodegenStatus {
        // Decrement SP
        self.ctx.stack_pop(1);
        CodegenStatus::KeepCompiling
    }

    fn gen_dup(&mut self) -> CodegenStatus {
        let dup_val = self.ctx.stack_opnd(0);
        let (mapping, tmp_type) = self.ctx.get_opnd_mapping(dup_val.into());

        let loc0 = self.ctx.stack_push_mapping((mapping, tmp_type));
        self.asm.mov(loc0, dup_val);

        CodegenStatus::KeepCompiling
    }

    // duplicate stack top n elements
    fn gen_dupn(&mut self) -> CodegenStatus {
        let n = self.jit.get_arg(0).as_usize();

        // In practice, seems to be only used for n==2
        if n != 2 {
            return CodegenStatus::CantCompile;
        }

        let opnd1: Opnd = self.ctx.stack_opnd(1);
        let opnd0: Opnd = self.ctx.stack_opnd(0);

        let mapping1 = self.ctx.get_opnd_mapping(opnd1.into());
        let mapping0 = self.ctx.get_opnd_mapping(opnd0.into());

        let dst1: Opnd = self.ctx.stack_push_mapping(mapping1);
        self.asm.mov(dst1, opnd1);

        let dst0: Opnd = self.ctx.stack_push_mapping(mapping0);
        self.asm.mov(dst0, opnd0);

        CodegenStatus::KeepCompiling
    }

    // Swap top 2 stack entries
    fn gen_swap(&mut self) -> CodegenStatus {
        self.stack_swap(0, 1);
        CodegenStatus::KeepCompiling
    }

    fn stack_swap(&mut self, offset0: u16, offset1: u16) {
        let stack0_mem = self.ctx.stack_opnd(offset0 as i32);
        let stack1_mem = self.ctx.stack_opnd(offset1 as i32);

        let mapping0 = self.ctx.get_opnd_mapping(stack0_mem.into());
        let mapping1 = self.ctx.get_opnd_mapping(stack1_mem.into());

        let stack0_reg = self.asm.load(stack0_mem);
        let stack1_reg = self.asm.load(stack1_mem);
        self.asm.mov(stack0_mem, stack1_reg);
        self.asm.mov(stack1_mem, stack0_reg);

        self.ctx.set_opnd_mapping(stack0_mem.into(), mapping1);
        self.ctx.set_opnd_mapping(stack1_mem.into(), mapping0);
    }

    fn gen_putnil(&mut self) -> CodegenStatus {
        self.jit_putobject(Qnil);
        CodegenStatus::KeepCompiling
    }

    fn jit_putobject(&mut self, arg: VALUE) {
        let val_type: Type = Type::from(arg);
        let stack_top = self.ctx.stack_push(val_type);
        self.asm.mov(stack_top, arg.into());
    }

    fn gen_putobject_int2fix(&mut self) -> CodegenStatus {
        let opcode = self.jit.opcode;
        let cst_val: usize = if opcode == YARVINSN_putobject_INT2FIX_0_.into_usize() {
            0
        } else {
            1
        };

        self.jit_putobject(VALUE::fixnum_from_usize(cst_val));
        CodegenStatus::KeepCompiling
    }

    fn gen_putobject(&mut self) -> CodegenStatus {
        let arg: VALUE = self.jit.get_arg(0);

        self.jit_putobject(arg);
        CodegenStatus::KeepCompiling
    }

    fn gen_putself(&mut self) -> CodegenStatus {
        // Write it on the stack
        let stack_top = self.ctx.stack_push_self();
        self.asm
            .mov(stack_top, Opnd::mem(VALUE_BITS, CFP, RUBY_OFFSET_CFP_SELF));

        CodegenStatus::KeepCompiling
    }

    fn gen_putspecialobject(&mut self) -> CodegenStatus {
        let object_type = self.jit.get_arg(0).as_usize();

        if object_type == VM_SPECIAL_OBJECT_VMCORE.into_usize() {
            let stack_top = self.ctx.stack_push(Type::UnknownHeap);
            let frozen_core = unsafe { rb_mRubyVMFrozenCore };
            self.asm.mov(stack_top, frozen_core.into());
            CodegenStatus::KeepCompiling
        } else {
            // TODO: implement for VM_SPECIAL_OBJECT_CBASE and
            // VM_SPECIAL_OBJECT_CONST_BASE
            CodegenStatus::CantCompile
        }
    }

    // set Nth stack entry to stack top
    fn gen_setn(&mut self) -> CodegenStatus {
        let n = self.jit.get_arg(0).as_usize();

        let top_val = self.ctx.stack_opnd(0);
        let dst_opnd = self.ctx.stack_opnd(n.try_into().unwrap());
        self.asm.mov(dst_opnd, top_val);

        let mapping = self.ctx.get_opnd_mapping(top_val.into());
        self.ctx.set_opnd_mapping(dst_opnd.into(), mapping);

        CodegenStatus::KeepCompiling
    }

    // get nth stack value, then push it
    fn gen_topn(&mut self) -> CodegenStatus {
        let n = self.jit.get_arg(0).as_usize();

        let top_n_val = self.ctx.stack_opnd(n.try_into().unwrap());
        let mapping = self.ctx.get_opnd_mapping(top_n_val.into());
        let loc0 = self.ctx.stack_push_mapping(mapping);
        self.asm.mov(loc0, top_n_val);

        CodegenStatus::KeepCompiling
    }

    // Pop n values off the stack
    fn gen_adjuststack(&mut self) -> CodegenStatus {
        let n = self.jit.get_arg(0).as_usize();
        self.ctx.stack_pop(n);
        CodegenStatus::KeepCompiling
    }

    fn gen_opt_plus(&mut self) -> CodegenStatus {
        let two_fixnums = match self.ctx.two_fixnums_on_stack(&mut self.jit) {
            Some(two_fixnums) => two_fixnums,
            None => {
                self.defer_compilation();
                return CodegenStatus::EndBlock;
            }
        };

        if two_fixnums {
            // Create a side-exit to fall back to the interpreter
            // Note: we generate the side-exit before popping operands from the stack
            let side_exit = self.get_side_exit(&self.ctx.clone());

            if !self.assume_bop_not_redefined(INTEGER_REDEFINED_OP_FLAG, BOP_PLUS) {
                return CodegenStatus::CantCompile;
            }

            // Check that both operands are fixnums
            self.guard_two_fixnums(side_exit);

            // Get the operands from the stack
            let arg1 = self.ctx.stack_pop(1);
            let arg0 = self.ctx.stack_pop(1);

            // Add arg0 + arg1 and test for overflow
            let arg0_untag = self.asm.sub(arg0, Opnd::Imm(1));
            let out_val = self.asm.add(arg0_untag, arg1);
            self.asm.jo(side_exit);

            // Push the output on the stack
            let dst = self.ctx.stack_push(Type::Fixnum);
            self.asm.mov(dst, out_val);

            CodegenStatus::KeepCompiling
        } else {
            self.gen_opt_send_without_block()
        }
    }

    // new array initialized from top N values
    fn gen_newarray(&mut self) -> CodegenStatus {
        let n = self.jit.get_arg(0).as_u32();

        // Save the PC and SP because we are allocating
        self.jit_prepare_routine_call();

        // If n is 0, then elts is never going to be read, so we can just pass null
        let values_ptr = if n == 0 {
            Opnd::UImm(0)
        } else {
            self.asm.comment("load pointer to array elts");
            let offset_magnitude = (SIZEOF_VALUE as u32) * n;
            let values_opnd = self.ctx.sp_opnd(-(offset_magnitude as isize));
            self.asm.lea(values_opnd)
        };

        // call rb_ec_ary_new_from_values(struct rb_execution_context_struct *ec, long n, const VALUE *elts);
        let new_ary = self.asm.ccall(
            rb_ec_ary_new_from_values as *const u8,
            vec![EC, Opnd::UImm(n.into()), values_ptr],
        );

        self.ctx.stack_pop(n.into_usize());
        let stack_ret = self.ctx.stack_push(Type::CArray);
        self.asm.mov(stack_ret, new_ary);

        CodegenStatus::KeepCompiling
    }

    // dup array
    fn gen_duparray(&mut self) -> CodegenStatus {
        let ary = self.jit.get_arg(0);

        // Save the PC and SP because we are allocating
        self.jit_prepare_routine_call();

        // call rb_ary_resurrect(VALUE ary);
        let new_ary = self
            .asm
            .ccall(rb_ary_resurrect as *const u8, vec![ary.into()]);

        let stack_ret = self.ctx.stack_push(Type::CArray);
        self.asm.mov(stack_ret, new_ary);

        CodegenStatus::KeepCompiling
    }

    // dup hash
    fn gen_duphash(&mut self) -> CodegenStatus {
        let hash = self.jit.get_arg(0);

        // Save the PC and SP because we are allocating
        self.jit_prepare_routine_call();

        // call rb_hash_resurrect(VALUE hash);
        let hash = self
            .asm
            .ccall(rb_hash_resurrect as *const u8, vec![hash.into()]);

        let stack_ret = self.ctx.stack_push(Type::Hash);
        self.asm.mov(stack_ret, hash);

        CodegenStatus::KeepCompiling
    }

    // call to_a on the array on the stack
    fn gen_splatarray(&mut self) -> CodegenStatus {
        let flag = self.jit.get_arg(0).as_usize();

        // Save the PC and SP because the callee may allocate
        // Note that this modifies REG_SP, which is why we do it first
        self.jit_prepare_routine_call();

        // Get the operands from the stack
        let ary_opnd = self.ctx.stack_pop(1);

        // Call rb_vm_splat_array(flag, ary)
        let ary = self
            .asm
            .ccall(rb_vm_splat_array as *const u8, vec![flag.into(), ary_opnd]);

        let stack_ret = self.ctx.stack_push(Type::TArray);
        self.asm.mov(stack_ret, ary);

        CodegenStatus::KeepCompiling
    }

    // concat two arrays
    fn gen_concatarray(&mut self) -> CodegenStatus {
        // Save the PC and SP because the callee may allocate
        // Note that this modifies REG_SP, which is why we do it first
        self.jit_prepare_routine_call();

        // Get the operands from the stack
        let ary2st_opnd = self.ctx.stack_pop(1);
        let ary1_opnd = self.ctx.stack_pop(1);

        // Call rb_vm_concat_array(ary1, ary2st)
        let ary = self.asm.ccall(
            rb_vm_concat_array as *const u8,
            vec![ary1_opnd, ary2st_opnd],
        );

        let stack_ret = self.ctx.stack_push(Type::TArray);
        self.asm.mov(stack_ret, ary);

        CodegenStatus::KeepCompiling
    }

    // new range initialized from top 2 values
    fn gen_newrange(&mut self) -> CodegenStatus {
        let flag = self.jit.get_arg(0).as_usize();

        // rb_range_new() allocates and can raise
        self.jit_prepare_routine_call();

        // val = rb_range_new(low, high, (int)flag);
        let range_opnd = self.asm.ccall(
            rb_range_new as *const u8,
            vec![self.ctx.stack_opnd(1), self.ctx.stack_opnd(0), flag.into()],
        );

        self.ctx.stack_pop(2);
        let stack_ret = self.ctx.stack_push(Type::UnknownHeap);
        self.asm.mov(stack_ret, range_opnd);

        CodegenStatus::KeepCompiling
    }

    fn guard_object_is_heap(&mut self, object: Opnd, object_opnd: YARVOpnd, side_exit: Target) {
        let object_type = self.ctx.get_opnd_type(object_opnd);
        if object_type.is_heap() {
            return;
        }

        self.asm.comment("guard object is heap");

        // Test that the object is not an immediate
        self.asm.test(object, (RUBY_IMMEDIATE_MASK as u64).into());
        self.asm.jnz(side_exit);

        // Test that the object is not false
        self.asm.cmp(object, Qfalse.into());
        self.asm.je(side_exit);

        if object_type.diff(Type::UnknownHeap) != TypeDiff::Incompatible {
            self.ctx.upgrade_opnd_type(object_opnd, Type::UnknownHeap);
        }
    }

    fn guard_object_is_array(&mut self, object: Opnd, object_opnd: YARVOpnd, side_exit: Target) {
        let object_type = self.ctx.get_opnd_type(object_opnd);
        if object_type.is_array() {
            return;
        }

        let object_reg = match object {
            Opnd::Reg(_) => object,
            _ => self.asm.load(object),
        };
        self.guard_object_is_heap(object_reg, object_opnd, side_exit);

        self.asm.comment("guard object is array");

        // Pull out the type mask
        let flags_opnd = Opnd::mem(VALUE_BITS, object_reg, RUBY_OFFSET_RBASIC_FLAGS);
        let flags_opnd = self.asm.and(flags_opnd, (RUBY_T_MASK as u64).into());

        // Compare the result with T_ARRAY
        self.asm.cmp(flags_opnd, (RUBY_T_ARRAY as u64).into());
        self.asm.jne(side_exit);

        if object_type.diff(Type::TArray) != TypeDiff::Incompatible {
            self.ctx.upgrade_opnd_type(object_opnd, Type::TArray);
        }
    }

    /// This guards that a special flag is not set on a hash.
    /// By passing a hash with this flag set as the last argument
    /// in a splat call, you can change the way keywords are handled
    /// to behave like ruby 2. We don't currently support this.
    fn guard_object_is_not_ruby2_keyword_hash(&mut self, object_opnd: Opnd, side_exit: Target) {
        self.asm.comment("guard object is not ruby2 keyword hash");

        let not_ruby2_keyword = self.asm.new_label("not_ruby2_keyword");
        self.asm
            .test(object_opnd, (RUBY_IMMEDIATE_MASK as u64).into());
        self.asm.jnz(not_ruby2_keyword);

        self.asm.cmp(object_opnd, Qfalse.into());
        self.asm.je(not_ruby2_keyword);

        let flags_opnd =
            self.asm
                .load(Opnd::mem(VALUE_BITS, object_opnd, RUBY_OFFSET_RBASIC_FLAGS));
        let type_opnd = self.asm.and(flags_opnd, (RUBY_T_MASK as u64).into());

        self.asm.cmp(type_opnd, (RUBY_T_HASH as u64).into());
        self.asm.jne(not_ruby2_keyword);

        self.asm
            .test(flags_opnd, (RHASH_PASS_AS_KEYWORDS as u64).into());
        self.asm.jnz(side_exit);

        self.asm.write_label(not_ruby2_keyword);
    }

    fn guard_object_is_string(&mut self, object_reg: Opnd, side_exit: Target) {
        self.asm.comment("guard object is string");

        // Pull out the type mask
        let flags_reg = self
            .asm
            .load(Opnd::mem(VALUE_BITS, object_reg, RUBY_OFFSET_RBASIC_FLAGS));
        let flags_reg = self.asm.and(flags_reg, Opnd::UImm(RUBY_T_MASK as u64));

        // Compare the result with T_STRING
        self.asm.cmp(flags_reg, Opnd::UImm(RUBY_T_STRING as u64));
        self.asm.jne(side_exit);
    }

    // push enough nils onto the stack to fill out an array
    fn gen_expandarray(&mut self) -> CodegenStatus {
        // Both arguments are rb_num_t which is unsigned
        let num = self.jit.get_arg(0).as_usize();
        let flag = self.jit.get_arg(1).as_usize();

        // If this instruction has the splat flag, then bail out.
        if flag & 0x01 != 0 {
            gen_counter_incr!(self.asm, expandarray_splat);
            return CodegenStatus::CantCompile;
        }

        // If this instruction has the postarg flag, then bail out.
        if flag & 0x02 != 0 {
            gen_counter_incr!(self.asm, expandarray_postarg);
            return CodegenStatus::CantCompile;
        }

        let side_exit = self.get_side_exit(&self.ctx.clone());

        let array_opnd = self.ctx.stack_opnd(0);

        // num is the number of requested values. If there aren't enough in the
        // array then we're going to push on nils.
        if self.ctx.get_opnd_type(array_opnd.into()) == Type::Nil {
            self.ctx.stack_pop(1); // pop after using the type info
                                   // special case for a, b = nil pattern
                                   // push N nils onto the stack
            for _ in 0..num {
                let push_opnd = self.ctx.stack_push(Type::Nil);
                self.asm.mov(push_opnd, Qnil.into());
            }
            return CodegenStatus::KeepCompiling;
        }

        // Move the array from the stack and check that it's an array.
        let exit = counted_exit!(self.get_ocb(), side_exit, expandarray_not_array);
        self.guard_object_is_array(array_opnd, array_opnd.into(), exit);
        let array_opnd = self.ctx.stack_pop(1); // pop after using the type info

        // If we don't actually want any values, then just return.
        if num == 0 {
            return CodegenStatus::KeepCompiling;
        }

        let array_reg = self.asm.load(array_opnd);
        let array_len_opnd = self.get_array_len(array_reg);

        // Only handle the case where the number of values in the array is greater
        // than or equal to the number of values requested.
        self.asm.cmp(array_len_opnd, num.into());
        let exit = counted_exit!(self.get_ocb(), side_exit, expandarray_rhs_too_small);
        self.asm.jl(exit);

        // Load the address of the embedded array into REG1.
        // (struct RArray *)(obj)->as.ary
        let array_reg = self.asm.load(array_opnd);
        let ary_opnd = self
            .asm
            .lea(Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RARRAY_AS_ARY));

        // Conditionally load the address of the heap array into REG1.
        // (struct RArray *)(obj)->as.heap.ptr
        let flags_opnd = Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RBASIC_FLAGS);
        self.asm
            .test(flags_opnd, Opnd::UImm(RARRAY_EMBED_FLAG as u64));
        let heap_ptr_opnd = Opnd::mem(
            usize::BITS as u8,
            self.asm.load(array_opnd),
            RUBY_OFFSET_RARRAY_AS_HEAP_PTR,
        );
        let ary_opnd = self.asm.csel_nz(ary_opnd, heap_ptr_opnd);

        // Loop backward through the array and push each element onto the stack.
        for i in (0..num).rev() {
            let top = self.ctx.stack_push(Type::Unknown);
            let offset = i32::try_from(i * SIZEOF_VALUE).unwrap();
            self.asm.mov(top, Opnd::mem(64, ary_opnd, offset));
        }

        CodegenStatus::KeepCompiling
    }

    // Compute the index of a local variable from its slot index
    fn ep_offset_to_local_idx(&mut self, ep_offset: u32) -> u32 {
        // Layout illustration
        // This is an array of VALUE
        //                                           | VM_ENV_DATA_SIZE |
        //                                           v                  v
        // low addr <+-------+-------+-------+-------+------------------+
        //           |local 0|local 1|  ...  |local n|       ....       |
        //           +-------+-------+-------+-------+------------------+
        //           ^       ^                       ^                  ^
        //           +-------+---local_table_size----+         cfp->ep--+
        //                   |                                          |
        //                   +------------------ep_offset---------------+
        //
        // See usages of local_var_name() from iseq.c for similar calculation.

        // Equivalent of iseq->body->local_table_size
        let local_table_size: i32 = unsafe { get_iseq_body_local_table_size(self.jit.iseq) }
            .try_into()
            .unwrap();
        let op = (ep_offset - VM_ENV_DATA_SIZE) as i32;
        let local_idx = local_table_size - op - 1;
        assert!(local_idx >= 0 && local_idx < local_table_size);
        local_idx.try_into().unwrap()
    }

    // Get EP at level from CFP
    fn gen_get_ep(&mut self, level: u32) -> Opnd {
        // Load environment pointer EP from CFP into a register
        let ep_opnd = Opnd::mem(64, CFP, RUBY_OFFSET_CFP_EP);
        let mut ep_opnd = self.asm.load(ep_opnd);

        for _ in (0..level).rev() {
            // Get the previous EP from the current EP
            // See GET_PREV_EP(ep) macro
            // VALUE *prev_ep = ((VALUE *)((ep)[VM_ENV_DATA_INDEX_SPECVAL] & ~0x03))
            let offs = SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_SPECVAL;
            ep_opnd = self.asm.load(Opnd::mem(64, ep_opnd, offs));
            ep_opnd = self.asm.and(ep_opnd, Opnd::Imm(!0x03));
        }

        ep_opnd
    }

    // Gets the EP of the ISeq of the containing method, or "local level".
    // Equivalent of GET_LEP() macro.
    fn gen_get_lep(&mut self) -> Opnd {
        // Equivalent of get_lvar_level() in compile.c
        fn get_lvar_level(iseq: IseqPtr) -> u32 {
            if iseq == unsafe { rb_get_iseq_body_local_iseq(iseq) } {
                0
            } else {
                1 + get_lvar_level(unsafe { rb_get_iseq_body_parent_iseq(iseq) })
            }
        }

        let level = get_lvar_level(self.jit.get_iseq());
        self.gen_get_ep(level)
    }

    fn gen_getlocal_generic(&mut self, ep_offset: u32, level: u32) -> CodegenStatus {
        // Load environment pointer EP (level 0) from CFP
        let ep_opnd = self.gen_get_ep(level);

        // Load the local from the block
        // val = *(vm_get_ep(GET_EP(), level) - idx);
        let offs = -(SIZEOF_VALUE_I32 * ep_offset as i32);
        let local_opnd = Opnd::mem(64, ep_opnd, offs);

        // Write the local at SP
        let stack_top = if level == 0 {
            let local_idx = self.ep_offset_to_local_idx(ep_offset);
            self.ctx.stack_push_local(local_idx.into_usize())
        } else {
            self.ctx.stack_push(Type::Unknown)
        };

        self.asm.mov(stack_top, local_opnd);

        CodegenStatus::KeepCompiling
    }

    fn gen_getlocal(&mut self) -> CodegenStatus {
        let idx = self.jit.get_arg(0).as_u32();
        let level = self.jit.get_arg(1).as_u32();
        self.gen_getlocal_generic(idx, level)
    }

    fn gen_getlocal_wc0(&mut self) -> CodegenStatus {
        let idx = self.jit.get_arg(0).as_u32();
        self.gen_getlocal_generic(idx, 0)
    }

    fn gen_getlocal_wc1(&mut self) -> CodegenStatus {
        let idx = self.jit.get_arg(0).as_u32();
        self.gen_getlocal_generic(idx, 1)
    }

    fn gen_setlocal_generic(&mut self, ep_offset: u32, level: u32) -> CodegenStatus {
        let value_type = self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0));

        // Load environment pointer EP at level
        let ep_opnd = self.gen_get_ep(level);

        // Write barriers may be required when VM_ENV_FLAG_WB_REQUIRED is set, however write barriers
        // only affect heap objects being written. If we know an immediate value is being written we
        // can skip this check.
        if !value_type.is_imm() {
            // flags & VM_ENV_FLAG_WB_REQUIRED
            let flags_opnd = Opnd::mem(
                64,
                ep_opnd,
                SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_FLAGS as i32,
            );
            self.asm.test(flags_opnd, VM_ENV_FLAG_WB_REQUIRED.into());

            // Create a side-exit to fall back to the interpreter
            let side_exit = self.get_side_exit(&self.ctx.clone());

            // if (flags & VM_ENV_FLAG_WB_REQUIRED) != 0
            self.asm.jnz(side_exit);
        }

        if level == 0 {
            let local_idx = self.ep_offset_to_local_idx(ep_offset).into_usize();
            self.ctx.set_local_type(local_idx, value_type);
        }

        // Pop the value to write from the stack
        let stack_top = self.ctx.stack_pop(1);

        // Write the value at the environment pointer
        let offs = -(SIZEOF_VALUE_I32 * ep_offset as i32);
        self.asm.mov(Opnd::mem(64, ep_opnd, offs), stack_top);

        CodegenStatus::KeepCompiling
    }

    fn gen_setlocal(&mut self) -> CodegenStatus {
        let idx = self.jit.get_arg(0).as_u32();
        let level = self.jit.get_arg(1).as_u32();
        self.gen_setlocal_generic(idx, level)
    }

    fn gen_setlocal_wc0(&mut self) -> CodegenStatus {
        let idx = self.jit.get_arg(0).as_u32();
        self.gen_setlocal_generic(idx, 0)
    }

    fn gen_setlocal_wc1(&mut self) -> CodegenStatus {
        let idx = self.jit.get_arg(0).as_u32();
        self.gen_setlocal_generic(idx, 1)
    }

    // new hash initialized from top N values
    fn gen_newhash(&mut self) -> CodegenStatus {
        let num: u64 = self.jit.get_arg(0).as_u64();

        // Save the PC and SP because we are allocating
        self.jit_prepare_routine_call();

        if num != 0 {
            // val = rb_hash_new_with_size(num / 2);
            let new_hash = self.asm.ccall(
                rb_hash_new_with_size as *const u8,
                vec![Opnd::UImm(num / 2)],
            );

            // Save the allocated hash as we want to push it after insertion
            self.asm.cpush(new_hash);
            self.asm.cpush(new_hash); // x86 alignment

            // Get a pointer to the values to insert into the hash
            let stack_addr_from_top = self.asm.lea(self.ctx.stack_opnd((num - 1) as i32));

            // rb_hash_bulk_insert(num, STACK_ADDR_FROM_TOP(num), val);
            self.asm.ccall(
                rb_hash_bulk_insert as *const u8,
                vec![Opnd::UImm(num), stack_addr_from_top, new_hash],
            );

            let new_hash = self.asm.cpop();
            self.asm.cpop_into(new_hash); // x86 alignment

            self.ctx.stack_pop(num.try_into().unwrap());
            let stack_ret = self.ctx.stack_push(Type::Hash);
            self.asm.mov(stack_ret, new_hash);
        } else {
            // val = rb_hash_new();
            let new_hash = self.asm.ccall(rb_hash_new as *const u8, vec![]);
            let stack_ret = self.ctx.stack_push(Type::Hash);
            self.asm.mov(stack_ret, new_hash);
        }

        CodegenStatus::KeepCompiling
    }

    fn gen_putstring(&mut self) -> CodegenStatus {
        let put_val = self.jit.get_arg(0);

        // Save the PC and SP because the callee will allocate
        self.jit_prepare_routine_call();

        let str_opnd = self
            .asm
            .ccall(rb_ec_str_resurrect as *const u8, vec![EC, put_val.into()]);

        let stack_top = self.ctx.stack_push(Type::CString);
        self.asm.mov(stack_top, str_opnd);

        CodegenStatus::KeepCompiling
    }

    // Push Qtrue or Qfalse depending on whether the given keyword was supplied by
    // the caller
    fn gen_checkkeyword(&mut self) -> CodegenStatus {
        // When a keyword is unspecified past index 32, a hash will be used
        // instead. This can only happen in iseqs taking more than 32 keywords.
        if unsafe { (*get_iseq_body_param_keyword(self.jit.iseq)).num >= 32 } {
            return CodegenStatus::CantCompile;
        }

        // The EP offset to the undefined bits local
        let bits_offset = self.jit.get_arg(0).as_i32();

        // The index of the keyword we want to check
        let index: i64 = self.jit.get_arg(1).as_i64();

        // Load environment pointer EP
        let ep_opnd = self.gen_get_ep(0);

        // VALUE kw_bits = *(ep - bits);
        let bits_opnd = Opnd::mem(64, ep_opnd, SIZEOF_VALUE_I32 * -bits_offset);

        // unsigned int b = (unsigned int)FIX2ULONG(kw_bits);
        // if ((b & (0x01 << idx))) {
        //
        // We can skip the FIX2ULONG conversion by shifting the bit we test
        let bit_test: i64 = 0x01 << (index + 1);
        self.asm.test(bits_opnd, Opnd::Imm(bit_test));
        let ret_opnd = self.asm.csel_z(Qtrue.into(), Qfalse.into());

        let stack_ret = self.ctx.stack_push(Type::UnknownImm);
        self.asm.mov(stack_ret, ret_opnd);

        CodegenStatus::KeepCompiling
    }

    // Generate a jump to a stub that recompiles the current YARV instruction on failure.
    // When depth_limit is exceeded, generate a jump to a side exit.
    fn jit_chain_guard(
        &mut self,
        ctx: &Context,
        jcc: JCCKinds,
        depth_limit: i32,
        side_exit: Target,
    ) {
        let target0_gen_fn = match jcc {
            JCC_JNE | JCC_JNZ => BranchGenFn::JNZToTarget0,
            JCC_JZ | JCC_JE => BranchGenFn::JZToTarget0,
            JCC_JBE | JCC_JNA => BranchGenFn::JBEToTarget0,
        };

        if (ctx.get_chain_depth() as i32) < depth_limit {
            let mut deeper = ctx.clone();
            deeper.increment_chain_depth();
            let bid = BlockId {
                iseq: self.jit.iseq,
                idx: self.jit.insn_idx,
            };
            gen_branch(self, bid, &deeper, None, None, target0_gen_fn);
        } else {
            target0_gen_fn.call(&mut self.asm, side_exit.unwrap_code_ptr(), None);
        }
    }

    // Codegen for setting an instance variable.
    // Preconditions:
    //   - receiver is in REG0
    //   - receiver has the same class as CLASS_OF(comptime_receiver)
    //   - no stack push or pops to ctx since the entry to the codegen of the instruction being compiled
    fn gen_set_ivar(&mut self, ivar_name: ID, call_info: CallInfo, argc: i32) -> CodegenStatus {
        // This is a .send call and we need to adjust the stack
        if call_info.flags.is_opt_send() {
            self.handle_opt_send_shift_stack(argc);
        }

        // Save the PC and SP because the callee may allocate
        // Note that this modifies REG_SP, which is why we do it first
        self.jit_prepare_routine_call();

        // Get the operands from the stack
        let val_opnd = self.ctx.stack_pop(1);
        let recv_opnd = self.ctx.stack_pop(1);

        // Call rb_vm_set_ivar_id with the receiver, the ivar name, and the value
        let val = self.asm.ccall(
            rb_vm_set_ivar_id as *const u8,
            vec![recv_opnd, Opnd::UImm(ivar_name), val_opnd],
        );

        let out_opnd = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(out_opnd, val);

        CodegenStatus::KeepCompiling
    }

    // Codegen for getting an instance variable.
    // Preconditions:
    //   - receiver has the same class as CLASS_OF(comptime_receiver)
    //   - no stack push or pops to ctx since the entry to the codegen of the instruction being compiled
    fn gen_get_ivar(
        &mut self,
        max_chain_depth: i32,
        comptime_receiver: VALUE,
        ivar_name: ID,
        recv: Opnd,
        recv_opnd: YARVOpnd,
        side_exit: Target,
    ) -> CodegenStatus {
        let comptime_val_klass = comptime_receiver.class_of();
        let starting_context = self.ctx.clone(); // make a copy for use with jit_chain_guard

        // If recv isn't already a register, load it.
        let recv = match recv {
            Opnd::Reg(_) => recv,
            _ => self.asm.load(recv),
        };

        // Check if the comptime class uses a custom allocator
        let custom_allocator = unsafe { rb_get_alloc_func(comptime_val_klass) };
        let uses_custom_allocator = match custom_allocator {
            Some(alloc_fun) => {
                let allocate_instance = rb_class_allocate_instance as *const u8;
                alloc_fun as *const u8 != allocate_instance
            }
            None => false,
        };

        // Check if the comptime receiver is a T_OBJECT
        let receiver_t_object = unsafe { RB_TYPE_P(comptime_receiver, RUBY_T_OBJECT) };
        // Use a general C call at the last chain to avoid exits on megamorphic shapes
        let last_chain = self.ctx.get_chain_depth() as i32 == max_chain_depth - 1;
        if last_chain {
            gen_counter_incr!(self.asm, get_ivar_max_depth);
        }

        // If the class uses the default allocator, instances should all be T_OBJECT
        // NOTE: This assumes nobody changes the allocator of the class after allocation.
        //       Eventually, we can encode whether an object is T_OBJECT or not
        //       inside object shapes.
        // too-complex shapes can't use index access, so we use rb_ivar_get for them too.
        if !receiver_t_object
            || uses_custom_allocator
            || comptime_receiver.shape_too_complex()
            || last_chain
        {
            // General case. Call rb_ivar_get().
            // VALUE rb_ivar_get(VALUE obj, ID id)
            self.asm.comment("call rb_ivar_get()");

            // The function could raise exceptions.
            self.jit_prepare_routine_call();

            let ivar_val = self
                .asm
                .ccall(rb_ivar_get as *const u8, vec![recv, Opnd::UImm(ivar_name)]);

            if recv_opnd != YARVOpnd::SelfOpnd {
                self.ctx.stack_pop(1);
            }

            // Push the ivar on the stack
            let out_opnd = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(out_opnd, ivar_val);

            // Jump to next instruction. This allows guard chains to share the same successor.
            self.jump_to_next_insn();
            return CodegenStatus::EndBlock;
        }

        let ivar_index = unsafe {
            let shape_id = comptime_receiver.shape_id_of();
            let shape = rb_shape_get_shape_by_id(shape_id);
            let mut ivar_index: u32 = 0;
            if rb_shape_get_iv_index(shape, ivar_name, &mut ivar_index) {
                Some(ivar_index as usize)
            } else {
                None
            }
        };

        // Guard heap object (recv_opnd must be used before stack_pop)
        self.guard_object_is_heap(recv, recv_opnd, side_exit);

        // Pop receiver if it's on the temp stack
        if recv_opnd != YARVOpnd::SelfOpnd {
            self.ctx.stack_pop(1);
        }

        // Compile time self is embedded and the ivar index lands within the object
        let embed_test_result = unsafe {
            FL_TEST_RAW(comptime_receiver, VALUE(ROBJECT_EMBED.into_usize())) != VALUE(0)
        };

        let expected_shape = unsafe { rb_shape_get_shape_id(comptime_receiver) };
        let shape_id_offset = unsafe { rb_shape_id_offset() };
        let shape_opnd = Opnd::mem(SHAPE_ID_NUM_BITS as u8, recv, shape_id_offset);

        self.asm.comment("guard shape");
        self.asm.cmp(shape_opnd, Opnd::UImm(expected_shape as u64));
        let megamorphic_side_exit = counted_exit!(self.get_ocb(), side_exit, getivar_megamorphic);
        self.jit_chain_guard(
            &starting_context,
            JCC_JNE,
            max_chain_depth,
            megamorphic_side_exit,
        );

        match ivar_index {
            // If there is no IVAR index, then the ivar was undefined
            // when we entered the compiler.  That means we can just return
            // nil for this shape + iv name
            None => {
                let out_opnd = self.ctx.stack_push(Type::Nil);
                self.asm.mov(out_opnd, Qnil.into());
            }
            Some(ivar_index) => {
                if embed_test_result {
                    // See ROBJECT_IVPTR() from include/ruby/internal/core/robject.h

                    // Load the variable
                    let offs = ROBJECT_OFFSET_AS_ARY + (ivar_index * SIZEOF_VALUE) as i32;
                    let ivar_opnd = Opnd::mem(64, recv, offs);

                    // Push the ivar on the stack
                    let out_opnd = self.ctx.stack_push(Type::Unknown);
                    self.asm.mov(out_opnd, ivar_opnd);
                } else {
                    // Compile time value is *not* embedded.

                    // Get a pointer to the extended table
                    let tbl_opnd = self
                        .asm
                        .load(Opnd::mem(64, recv, ROBJECT_OFFSET_AS_HEAP_IVPTR));

                    // Read the ivar from the extended table
                    let ivar_opnd = Opnd::mem(64, tbl_opnd, (SIZEOF_VALUE * ivar_index) as i32);

                    let out_opnd = self.ctx.stack_push(Type::Unknown);
                    self.asm.mov(out_opnd, ivar_opnd);
                }
            }
        }

        // Jump to next instruction. This allows guard chains to share the same successor.
        self.jump_to_next_insn();
        CodegenStatus::EndBlock
    }

    fn gen_getinstancevariable(&mut self) -> CodegenStatus {
        // Defer compilation so we can specialize on a runtime `self`
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        let ivar_name = self.jit.get_arg(0).as_u64();

        let comptime_val = self.jit.peek_at_self();

        // Generate a side exit
        let side_exit = self.get_side_exit(&self.ctx.clone());

        // Guard that the receiver has the same class as the one from compile time.
        let self_asm_opnd = Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SELF);

        self.gen_get_ivar(
            GET_IVAR_MAX_DEPTH,
            comptime_val,
            ivar_name,
            self_asm_opnd,
            YARVOpnd::SelfOpnd,
            side_exit,
        )
    }

    // Generate an IV write.
    // This function doesn't deal with writing the shape, or expanding an object
    // to use an IV buffer if necessary.  That is the callers responsibility
    fn gen_write_iv(
        &mut self,
        comptime_receiver: VALUE,
        recv: Opnd,
        ivar_index: usize,
        set_value: Opnd,
        extension_needed: bool,
    ) {
        // Compile time self is embedded and the ivar index lands within the object
        let embed_test_result = comptime_receiver.embedded_p() && !extension_needed;

        if embed_test_result {
            // Find the IV offset
            let offs = ROBJECT_OFFSET_AS_ARY + (ivar_index * SIZEOF_VALUE) as i32;
            let ivar_opnd = Opnd::mem(64, recv, offs);

            // Write the IV
            self.asm.comment("write IV");
            self.asm.mov(ivar_opnd, set_value);
        } else {
            // Compile time value is *not* embedded.

            // Get a pointer to the extended table
            let tbl_opnd = self
                .asm
                .load(Opnd::mem(64, recv, ROBJECT_OFFSET_AS_HEAP_IVPTR));

            // Write the ivar in to the extended table
            let ivar_opnd = Opnd::mem(64, tbl_opnd, (SIZEOF_VALUE * ivar_index) as i32);

            self.asm.comment("write IV");
            self.asm.mov(ivar_opnd, set_value);
        }
    }

    fn gen_setinstancevariable(&mut self) -> CodegenStatus {
        let starting_context = self.ctx.clone(); // make a copy for use with jit_chain_guard

        // Defer compilation so we can specialize on a runtime `self`
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        let ivar_name = self.jit.get_arg(0).as_u64();
        let comptime_receiver = self.jit.peek_at_self();
        let comptime_val_klass = comptime_receiver.class_of();

        // If the comptime receiver is frozen, writing an IV will raise an exception
        // and we don't want to JIT code to deal with that situation.
        if comptime_receiver.is_frozen() {
            gen_counter_incr!(self.asm, setivar_frozen);
            return CodegenStatus::CantCompile;
        }

        let (_, stack_type) = self.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

        // Check if the comptime class uses a custom allocator
        let custom_allocator = unsafe { rb_get_alloc_func(comptime_val_klass) };
        let uses_custom_allocator = match custom_allocator {
            Some(alloc_fun) => {
                let allocate_instance = rb_class_allocate_instance as *const u8;
                alloc_fun as *const u8 != allocate_instance
            }
            None => false,
        };

        // Check if the comptime receiver is a T_OBJECT
        let receiver_t_object = unsafe { RB_TYPE_P(comptime_receiver, RUBY_T_OBJECT) };

        // If the receiver isn't a T_OBJECT, or uses a custom allocator,
        // then just write out the IV write as a function call.
        // too-complex shapes can't use index access, so we use rb_ivar_get for them too.
        if !receiver_t_object
            || uses_custom_allocator
            || comptime_receiver.shape_too_complex()
            || (self.ctx.get_chain_depth() as i32) >= SET_IVAR_MAX_DEPTH
        {
            self.asm.comment("call rb_vm_setinstancevariable()");

            let ic = self.jit.get_arg(1).as_u64(); // type IVC

            // The function could raise exceptions.
            // Note that this modifies REG_SP, which is why we do it first
            self.jit_prepare_routine_call();

            // Get the operands from the stack
            let val_opnd = self.ctx.stack_pop(1);

            // Call rb_vm_setinstancevariable(iseq, obj, id, val, ic);
            self.asm.ccall(
                rb_vm_setinstancevariable as *const u8,
                vec![
                    Opnd::const_ptr(self.jit.iseq as *const u8),
                    Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SELF),
                    ivar_name.into(),
                    val_opnd,
                    Opnd::const_ptr(ic as *const u8),
                ],
            );
        } else {
            // Get the iv index
            let ivar_index = unsafe {
                let shape_id = comptime_receiver.shape_id_of();
                let shape = rb_shape_get_shape_by_id(shape_id);
                let mut ivar_index: u32 = 0;
                if rb_shape_get_iv_index(shape, ivar_name, &mut ivar_index) {
                    Some(ivar_index as usize)
                } else {
                    None
                }
            };

            // Get the receiver
            let mut recv = self.asm.load(Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SELF));

            let recv_opnd = YARVOpnd::SelfOpnd;

            // Generate a side exit
            let side_exit = self.get_side_exit(&self.ctx.clone());

            // Upgrade type
            self.guard_object_is_heap(recv, recv_opnd, side_exit);

            let expected_shape = unsafe { rb_shape_get_shape_id(comptime_receiver) };
            let shape_id_offset = unsafe { rb_shape_id_offset() };
            let shape_opnd = Opnd::mem(SHAPE_ID_NUM_BITS as u8, recv, shape_id_offset);

            self.asm.comment("guard shape");
            self.asm.cmp(shape_opnd, Opnd::UImm(expected_shape as u64));
            let megamorphic_side_exit =
                counted_exit!(self.get_ocb(), side_exit, setivar_megamorphic);
            self.jit_chain_guard(
                &starting_context,
                JCC_JNE,
                SET_IVAR_MAX_DEPTH,
                megamorphic_side_exit,
            );

            let write_val;

            match ivar_index {
                // If we don't have an instance variable index, then we need to
                // transition out of the current shape.
                None => {
                    let shape = comptime_receiver.shape_of();

                    let current_capacity = unsafe { (*shape).capacity };
                    let new_capacity = current_capacity * 2;

                    // If the object doesn't have the capacity to store the IV,
                    // then we'll need to allocate it.
                    let needs_extension = unsafe { (*shape).next_iv_index >= current_capacity };

                    // We can write to the object, but we need to transition the shape
                    let ivar_index = unsafe { (*shape).next_iv_index } as usize;

                    let capa_shape = if needs_extension {
                        // We need to add an extended table to the object
                        // First, create an outgoing transition that increases the
                        // capacity
                        Some(unsafe { rb_shape_transition_shape_capa(shape, new_capacity) })
                    } else {
                        None
                    };

                    let dest_shape = if let Some(capa_shape) = capa_shape {
                        unsafe { rb_shape_get_next(capa_shape, comptime_receiver, ivar_name) }
                    } else {
                        unsafe { rb_shape_get_next(shape, comptime_receiver, ivar_name) }
                    };

                    let new_shape_id = unsafe { rb_shape_id(dest_shape) };

                    if new_shape_id == OBJ_TOO_COMPLEX_SHAPE_ID {
                        return CodegenStatus::CantCompile;
                    }

                    if needs_extension {
                        // Generate the C call so that runtime code will increase
                        // the capacity and set the buffer.
                        self.asm.ccall(
                            rb_ensure_iv_list_size as *const u8,
                            vec![
                                recv,
                                Opnd::UImm(current_capacity.into()),
                                Opnd::UImm(new_capacity.into()),
                            ],
                        );

                        // Load the receiver again after the function call
                        recv = self.asm.load(Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SELF))
                    }

                    write_val = self.ctx.stack_pop(1);
                    self.gen_write_iv(
                        comptime_receiver,
                        recv,
                        ivar_index,
                        write_val,
                        needs_extension,
                    );

                    self.asm.comment("write shape");

                    let shape_id_offset = unsafe { rb_shape_id_offset() };
                    let shape_opnd = Opnd::mem(SHAPE_ID_NUM_BITS as u8, recv, shape_id_offset);

                    // Store the new shape
                    self.asm.store(shape_opnd, Opnd::UImm(new_shape_id as u64));
                }

                Some(ivar_index) => {
                    // If the iv index already exists, then we don't need to
                    // transition to a new shape.  The reason is because we find
                    // the iv index by searching up the shape tree.  If we've
                    // made the transition already, then there's no reason to
                    // update the shape on the object.  Just set the IV.
                    write_val = self.ctx.stack_pop(1);
                    self.gen_write_iv(comptime_receiver, recv, ivar_index, write_val, false);
                }
            }

            // If we know the stack value is an immediate, there's no need to
            // generate WB code.
            if !stack_type.is_imm() {
                let skip_wb = self.asm.new_label("skip_wb");
                // If the value we're writing is an immediate, we don't need to WB
                self.asm
                    .test(write_val, (RUBY_IMMEDIATE_MASK as u64).into());
                self.asm.jnz(skip_wb);

                // If the value we're writing is nil or false, we don't need to WB
                self.asm.cmp(write_val, Qnil.into());
                self.asm.jbe(skip_wb);

                self.asm.comment("write barrier");
                self.asm
                    .ccall(rb_gc_writebarrier as *const u8, vec![recv, write_val]);

                self.asm.write_label(skip_wb);
            }
        }

        CodegenStatus::KeepCompiling
    }

    fn gen_defined(&mut self) -> CodegenStatus {
        let op_type = self.jit.get_arg(0).as_u64();
        let obj = self.jit.get_arg(1);
        let pushval = self.jit.get_arg(2);

        // Save the PC and SP because the callee may allocate
        // Note that this modifies REG_SP, which is why we do it first
        self.jit_prepare_routine_call();

        // Get the operands from the stack
        let v_opnd = self.ctx.stack_pop(1);

        // Call vm_defined(ec, reg_cfp, op_type, obj, v)
        let def_result = self.asm.ccall(
            rb_vm_defined as *const u8,
            vec![EC, CFP, op_type.into(), obj.into(), v_opnd],
        );

        // if (vm_defined(ec, GET_CFP(), op_type, obj, v)) {
        //  val = pushval;
        // }
        self.asm.test(def_result, Opnd::UImm(255));
        let out_value = self.asm.csel_nz(pushval.into(), Qnil.into());

        // Push the return value onto the stack
        let out_type = if pushval.special_const_p() {
            Type::UnknownImm
        } else {
            Type::Unknown
        };
        let stack_ret = self.ctx.stack_push(out_type);
        self.asm.mov(stack_ret, out_value);

        CodegenStatus::KeepCompiling
    }

    fn gen_checktype(&mut self) -> CodegenStatus {
        let type_val = self.jit.get_arg(0).as_u32();

        // Only three types are emitted by compile.c at the moment
        if let RUBY_T_STRING | RUBY_T_ARRAY | RUBY_T_HASH = type_val {
            let val_type = self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0));
            let val = self.asm.load(self.ctx.stack_pop(1));

            // Check if we know from type information
            if let Some(value_type) = val_type.known_value_type() {
                if value_type == type_val {
                    self.jit_putobject(Qtrue);
                    return CodegenStatus::KeepCompiling;
                } else {
                    self.jit_putobject(Qfalse);
                    return CodegenStatus::KeepCompiling;
                }
            }

            let ret = self.asm.new_label("ret");

            if !val_type.is_heap() {
                // if (SPECIAL_CONST_P(val)) {
                // Return Qfalse via REG1 if not on heap
                self.asm.test(val, (RUBY_IMMEDIATE_MASK as u64).into());
                self.asm.jnz(ret);
                self.asm.cmp(val, Qfalse.into());
                self.asm.je(ret);
            }

            // Check type on object
            let object_type = self.asm.and(
                Opnd::mem(64, val, RUBY_OFFSET_RBASIC_FLAGS),
                Opnd::UImm(RUBY_T_MASK.into()),
            );
            self.asm.cmp(object_type, Opnd::UImm(type_val.into()));
            let ret_opnd = self.asm.csel_e(Qtrue.into(), Qfalse.into());

            self.asm.write_label(ret);
            let stack_ret = self.ctx.stack_push(Type::UnknownImm);
            self.asm.mov(stack_ret, ret_opnd);

            CodegenStatus::KeepCompiling
        } else {
            CodegenStatus::CantCompile
        }
    }

    fn gen_concatstrings(&mut self) -> CodegenStatus {
        let n = self.jit.get_arg(0).as_usize();

        // Save the PC and SP because we are allocating
        self.jit_prepare_routine_call();

        let values_ptr = self
            .asm
            .lea(self.ctx.sp_opnd(-((SIZEOF_VALUE as isize) * n as isize)));

        // call rb_str_concat_literals(size_t n, const VALUE *strings);
        let return_value = self.asm.ccall(
            rb_str_concat_literals as *const u8,
            vec![n.into(), values_ptr],
        );

        self.ctx.stack_pop(n);
        let stack_ret = self.ctx.stack_push(Type::CString);
        self.asm.mov(stack_ret, return_value);

        CodegenStatus::KeepCompiling
    }

    fn guard_two_fixnums(&mut self, side_exit: Target) {
        // Get stack operands without popping them
        let arg1 = self.ctx.stack_opnd(0);
        let arg0 = self.ctx.stack_opnd(1);

        // Get the stack operand types
        let arg1_type = self.ctx.get_opnd_type(arg1.into());
        let arg0_type = self.ctx.get_opnd_type(arg0.into());

        if arg0_type.is_heap() || arg1_type.is_heap() {
            self.asm.comment("arg is heap object");
            self.asm.jmp(side_exit);
            return;
        }

        if arg0_type != Type::Fixnum && arg0_type.is_specific() {
            self.asm.comment("arg0 not fixnum");
            self.asm.jmp(side_exit);
            return;
        }

        if arg1_type != Type::Fixnum && arg1_type.is_specific() {
            self.asm.comment("arg1 not fixnum");
            self.asm.jmp(side_exit);
            return;
        }

        assert!(!arg0_type.is_heap());
        assert!(!arg1_type.is_heap());
        assert!(arg0_type == Type::Fixnum || arg0_type.is_unknown());
        assert!(arg1_type == Type::Fixnum || arg1_type.is_unknown());

        // If not fixnums at run-time, fall back
        if arg0_type != Type::Fixnum {
            self.asm.comment("guard arg0 fixnum");
            self.asm.test(arg0, Opnd::UImm(RUBY_FIXNUM_FLAG as u64));

            self.jit_chain_guard(&self.ctx.clone(), JCC_JZ, SEND_MAX_DEPTH, side_exit);
        }
        if arg1_type != Type::Fixnum {
            self.asm.comment("guard arg1 fixnum");
            self.asm.test(arg1, Opnd::UImm(RUBY_FIXNUM_FLAG as u64));

            self.jit_chain_guard(&self.ctx.clone(), JCC_JZ, SEND_MAX_DEPTH, side_exit);
        }

        // Set stack types in context
        self.ctx.upgrade_opnd_type(arg1.into(), Type::Fixnum);
        self.ctx.upgrade_opnd_type(arg0.into(), Type::Fixnum);
    }

    fn gen_fixnum_cmp(&mut self, cmov_op: CmovFn, bop: ruby_basic_operators) -> CodegenStatus {
        let two_fixnums = match self.ctx.two_fixnums_on_stack(&mut self.jit) {
            Some(two_fixnums) => two_fixnums,
            None => {
                // Defer compilation so we can specialize based on a runtime receiver
                self.defer_compilation();
                return CodegenStatus::EndBlock;
            }
        };

        if two_fixnums {
            // Create a side-exit to fall back to the interpreter
            // Note: we generate the side-exit before popping operands from the stack
            let side_exit = self.get_side_exit(&self.ctx.clone());

            if !self.assume_bop_not_redefined(INTEGER_REDEFINED_OP_FLAG, bop) {
                return CodegenStatus::CantCompile;
            }

            // Check that both operands are fixnums
            self.guard_two_fixnums(side_exit);

            // Get the operands from the stack
            let arg1 = self.ctx.stack_pop(1);
            let arg0 = self.ctx.stack_pop(1);

            // Compare the arguments
            self.asm.cmp(arg0, arg1);
            let bool_opnd = cmov_op(&mut self.asm, Qtrue.into(), Qfalse.into());

            // Push the output on the stack
            let dst = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(dst, bool_opnd);

            CodegenStatus::KeepCompiling
        } else {
            self.gen_opt_send_without_block()
        }
    }

    fn gen_opt_lt(&mut self) -> CodegenStatus {
        self.gen_fixnum_cmp(Assembler::csel_l, BOP_LT)
    }

    fn gen_opt_le(&mut self) -> CodegenStatus {
        self.gen_fixnum_cmp(Assembler::csel_le, BOP_LE)
    }

    fn gen_opt_ge(&mut self) -> CodegenStatus {
        self.gen_fixnum_cmp(Assembler::csel_ge, BOP_GE)
    }

    fn gen_opt_gt(&mut self) -> CodegenStatus {
        self.gen_fixnum_cmp(Assembler::csel_g, BOP_GT)
    }

    // Implements specialized equality for either two fixnum or two strings
    // Returns None if enough type information isn't available, Some(true)
    // if code was generated, otherwise Some(false).
    fn gen_equality_specialized(&mut self, gen_eq: bool) -> Option<bool> {
        // Create a side-exit to fall back to the interpreter
        let side_exit = self.get_side_exit(&self.ctx.clone());

        let a_opnd = self.ctx.stack_opnd(1);
        let b_opnd = self.ctx.stack_opnd(0);

        let two_fixnums = match self.ctx.two_fixnums_on_stack(&mut self.jit) {
            Some(two_fixnums) => two_fixnums,
            None => return None,
        };

        if two_fixnums {
            if !self.assume_bop_not_redefined(INTEGER_REDEFINED_OP_FLAG, BOP_EQ) {
                // if overridden, emit the generic version
                return Some(false);
            }

            self.guard_two_fixnums(side_exit);

            self.asm.cmp(a_opnd, b_opnd);
            let val = if gen_eq {
                self.asm.csel_e(Qtrue.into(), Qfalse.into())
            } else {
                self.asm.csel_ne(Qtrue.into(), Qfalse.into())
            };

            // Push the output on the stack
            self.ctx.stack_pop(2);
            let dst = self.ctx.stack_push(Type::UnknownImm);
            self.asm.mov(dst, val);

            return Some(true);
        }

        if !self.jit.at_current_insn() {
            return None;
        }
        let comptime_a = self.jit.peek_at_stack(&self.ctx, 1);
        let comptime_b = self.jit.peek_at_stack(&self.ctx, 0);

        if unsafe { comptime_a.class_of() == rb_cString && comptime_b.class_of() == rb_cString } {
            if !self.assume_bop_not_redefined(STRING_REDEFINED_OP_FLAG, BOP_EQ) {
                // if overridden, emit the generic version
                return Some(false);
            }

            // Guard that a is a String
            self.jit_guard_known_klass(
                unsafe { rb_cString },
                a_opnd,
                a_opnd.into(),
                comptime_a,
                SEND_MAX_DEPTH,
                side_exit,
            );

            let equal = self.asm.new_label("equal");
            let ret = self.asm.new_label("ret");

            // If they are equal by identity, return true
            self.asm.cmp(a_opnd, b_opnd);
            self.asm.je(equal);

            // Otherwise guard that b is a T_STRING (from type info) or String (from runtime guard)
            let btype = self.ctx.get_opnd_type(b_opnd.into());
            if btype.known_value_type() != Some(RUBY_T_STRING) {
                // Note: any T_STRING is valid here, but we check for a ::String for simplicity
                // To pass a mutable static variable (rb_cString) requires an unsafe block
                self.jit_guard_known_klass(
                    unsafe { rb_cString },
                    b_opnd,
                    b_opnd.into(),
                    comptime_b,
                    SEND_MAX_DEPTH,
                    side_exit,
                );
            }

            // Call rb_str_eql_internal(a, b)
            let val = self.asm.ccall(
                if gen_eq {
                    rb_str_eql_internal
                } else {
                    rb_str_neq_internal
                } as *const u8,
                vec![a_opnd, b_opnd],
            );

            // Push the output on the stack
            self.ctx.stack_pop(2);
            let dst = self.ctx.stack_push(Type::UnknownImm);
            self.asm.mov(dst, val);
            self.asm.jmp(ret);

            self.asm.write_label(equal);
            self.asm
                .mov(dst, if gen_eq { Qtrue } else { Qfalse }.into());

            self.asm.write_label(ret);

            Some(true)
        } else {
            Some(false)
        }
    }

    fn gen_opt_eq(&mut self) -> CodegenStatus {
        let specialized = match self.gen_equality_specialized(true) {
            Some(specialized) => specialized,
            None => {
                // Defer compilation so we can specialize base on a runtime receiver
                self.defer_compilation();
                return CodegenStatus::EndBlock;
            }
        };

        if specialized {
            self.jump_to_next_insn();
            CodegenStatus::EndBlock
        } else {
            self.gen_opt_send_without_block()
        }
    }

    fn gen_opt_neq(&mut self) -> CodegenStatus {
        // opt_neq is passed two rb_call_data as arguments:
        // first for ==, second for !=
        let cd = self.jit.get_arg(1).as_ptr();
        self.gen_send_general(cd, None)
    }

    fn gen_opt_aref(&mut self) -> CodegenStatus {
        let cd: *const rb_call_data = self.jit.get_arg(0).as_ptr();
        let argc = unsafe { vm_ci_argc((*cd).ci) };

        // Only JIT one arg calls like `ary[6]`
        if argc != 1 {
            gen_counter_incr!(self.asm, oaref_argc_not_one);
            return CodegenStatus::CantCompile;
        }

        // Defer compilation so we can specialize base on a runtime receiver
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        // Specialize base on compile time values
        let comptime_idx = self.jit.peek_at_stack(&self.ctx, 0);
        let comptime_recv = self.jit.peek_at_stack(&self.ctx, 1);

        // Create a side-exit to fall back to the interpreter
        let side_exit = self.get_side_exit(&self.ctx.clone());

        if comptime_recv.class_of() == unsafe { rb_cArray } && comptime_idx.fixnum_p() {
            if !self.assume_bop_not_redefined(ARRAY_REDEFINED_OP_FLAG, BOP_AREF) {
                return CodegenStatus::CantCompile;
            }

            // Get the stack operands
            let idx_opnd = self.ctx.stack_opnd(0);
            let recv_opnd = self.ctx.stack_opnd(1);

            // Guard that the receiver is an ::Array
            // BOP_AREF check above is only good for ::Array.
            self.jit_guard_known_klass(
                unsafe { rb_cArray },
                recv_opnd,
                recv_opnd.into(),
                comptime_recv,
                OPT_AREF_MAX_CHAIN_DEPTH,
                side_exit,
            );

            // Bail if idx is not a FIXNUM
            let idx_reg = self.asm.load(idx_opnd);
            self.asm.test(idx_reg, (RUBY_FIXNUM_FLAG as u64).into());
            let exit = counted_exit!(self.get_ocb(), side_exit, oaref_arg_not_fixnum);
            self.asm.jz(exit);

            // Call VALUE rb_ary_entry_internal(VALUE ary, long offset).
            // It never raises or allocates, so we don't need to write to cfp->pc.
            {
                let idx_reg = self.asm.rshift(idx_reg, Opnd::UImm(1)); // Convert fixnum to int
                let val = self
                    .asm
                    .ccall(rb_ary_entry_internal as *const u8, vec![recv_opnd, idx_reg]);

                // Pop the argument and the receiver
                self.ctx.stack_pop(2);

                // Push the return value onto the stack
                let stack_ret = self.ctx.stack_push(Type::Unknown);
                self.asm.mov(stack_ret, val);
            }

            // Jump to next instruction. This allows guard chains to share the same successor.
            self.jump_to_next_insn();
            CodegenStatus::EndBlock
        } else if comptime_recv.class_of() == unsafe { rb_cHash } {
            if !self.assume_bop_not_redefined(HASH_REDEFINED_OP_FLAG, BOP_AREF) {
                return CodegenStatus::CantCompile;
            }

            let recv_opnd = self.ctx.stack_opnd(1);

            // Guard that the receiver is a hash
            self.jit_guard_known_klass(
                unsafe { rb_cHash },
                recv_opnd,
                recv_opnd.into(),
                comptime_recv,
                OPT_AREF_MAX_CHAIN_DEPTH,
                side_exit,
            );

            // Prepare to call rb_hash_aref(). It might call #hash on the key.
            self.jit_prepare_routine_call();

            // Call rb_hash_aref
            let key_opnd = self.ctx.stack_opnd(0);
            let recv_opnd = self.ctx.stack_opnd(1);
            let val = self
                .asm
                .ccall(rb_hash_aref as *const u8, vec![recv_opnd, key_opnd]);

            // Pop the key and the receiver
            self.ctx.stack_pop(2);

            // Push the return value onto the stack
            let stack_ret = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(stack_ret, val);

            // Jump to next instruction. This allows guard chains to share the same successor.
            self.jump_to_next_insn();
            CodegenStatus::EndBlock
        } else {
            // General case. Call the [] method.
            self.gen_opt_send_without_block()
        }
    }

    fn gen_opt_aset(&mut self) -> CodegenStatus {
        // Defer compilation so we can specialize on a runtime `self`
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        let comptime_recv = self.jit.peek_at_stack(&self.ctx, 2);
        let comptime_key = self.jit.peek_at_stack(&self.ctx, 1);

        // Get the operands from the stack
        let recv = self.ctx.stack_opnd(2);
        let key = self.ctx.stack_opnd(1);
        let _val = self.ctx.stack_opnd(0);

        if comptime_recv.class_of() == unsafe { rb_cArray } && comptime_key.fixnum_p() {
            let side_exit = self.get_side_exit(&self.ctx.clone());

            // Guard receiver is an Array
            self.jit_guard_known_klass(
                unsafe { rb_cArray },
                recv,
                recv.into(),
                comptime_recv,
                SEND_MAX_DEPTH,
                side_exit,
            );

            // Guard key is a fixnum
            self.jit_guard_known_klass(
                unsafe { rb_cInteger },
                key,
                key.into(),
                comptime_key,
                SEND_MAX_DEPTH,
                side_exit,
            );

            // We might allocate or raise
            self.jit_prepare_routine_call();

            // Call rb_ary_store
            let recv = self.ctx.stack_opnd(2);
            let key = self.asm.load(self.ctx.stack_opnd(1));
            let key = self.asm.rshift(key, Opnd::UImm(1)); // FIX2LONG(key)
            let val = self.ctx.stack_opnd(0);
            self.asm
                .ccall(rb_ary_store as *const u8, vec![recv, key, val]);

            // rb_ary_store returns void
            // stored value should still be on stack
            let val = self.asm.load(self.ctx.stack_opnd(0));

            // Push the return value onto the stack
            self.ctx.stack_pop(3);
            let stack_ret = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(stack_ret, val);

            self.jump_to_next_insn();
            CodegenStatus::EndBlock
        } else if comptime_recv.class_of() == unsafe { rb_cHash } {
            let side_exit = self.get_side_exit(&self.ctx.clone());

            // Guard receiver is a Hash
            self.jit_guard_known_klass(
                unsafe { rb_cHash },
                recv,
                recv.into(),
                comptime_recv,
                SEND_MAX_DEPTH,
                side_exit,
            );

            // We might allocate or raise
            self.jit_prepare_routine_call();

            // Call rb_hash_aset
            let recv = self.ctx.stack_opnd(2);
            let key = self.ctx.stack_opnd(1);
            let val = self.ctx.stack_opnd(0);
            let ret = self
                .asm
                .ccall(rb_hash_aset as *const u8, vec![recv, key, val]);

            // Push the return value onto the stack
            self.ctx.stack_pop(3);
            let stack_ret = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(stack_ret, ret);

            self.jump_to_next_insn();
            CodegenStatus::EndBlock
        } else {
            self.gen_opt_send_without_block()
        }
    }

    fn gen_opt_and(&mut self) -> CodegenStatus {
        let two_fixnums = match self.ctx.two_fixnums_on_stack(&mut self.jit) {
            Some(two_fixnums) => two_fixnums,
            None => {
                // Defer compilation so we can specialize on a runtime `self`
                self.defer_compilation();
                return CodegenStatus::EndBlock;
            }
        };

        if two_fixnums {
            // Create a side-exit to fall back to the interpreter
            // Note: we generate the side-exit before popping operands from the stack
            let side_exit = self.get_side_exit(&self.ctx.clone());

            if !self.assume_bop_not_redefined(INTEGER_REDEFINED_OP_FLAG, BOP_AND) {
                return CodegenStatus::CantCompile;
            }

            // Check that both operands are fixnums
            self.guard_two_fixnums(side_exit);

            // Get the operands and destination from the stack
            let arg1 = self.ctx.stack_pop(1);
            let arg0 = self.ctx.stack_pop(1);

            // Do the bitwise and arg0 & arg1
            let val = self.asm.and(arg0, arg1);

            // Push the output on the stack
            let dst = self.ctx.stack_push(Type::Fixnum);
            self.asm.store(dst, val);

            CodegenStatus::KeepCompiling
        } else {
            // Delegate to send, call the method on the recv
            self.gen_opt_send_without_block()
        }
    }

    fn gen_opt_or(&mut self) -> CodegenStatus {
        let two_fixnums = match self.ctx.two_fixnums_on_stack(&mut self.jit) {
            Some(two_fixnums) => two_fixnums,
            None => {
                // Defer compilation so we can specialize on a runtime `self`
                self.defer_compilation();
                return CodegenStatus::EndBlock;
            }
        };

        if two_fixnums {
            // Create a side-exit to fall back to the interpreter
            // Note: we generate the side-exit before popping operands from the stack
            let side_exit = self.get_side_exit(&self.ctx.clone());

            if !self.assume_bop_not_redefined(INTEGER_REDEFINED_OP_FLAG, BOP_OR) {
                return CodegenStatus::CantCompile;
            }

            // Check that both operands are fixnums
            self.guard_two_fixnums(side_exit);

            // Get the operands and destination from the stack
            let arg1 = self.ctx.stack_pop(1);
            let arg0 = self.ctx.stack_pop(1);

            // Do the bitwise or arg0 | arg1
            let val = self.asm.or(arg0, arg1);

            // Push the output on the stack
            let dst = self.ctx.stack_push(Type::Fixnum);
            self.asm.store(dst, val);

            CodegenStatus::KeepCompiling
        } else {
            // Delegate to send, call the method on the recv
            self.gen_opt_send_without_block()
        }
    }

    fn gen_opt_minus(&mut self) -> CodegenStatus {
        let two_fixnums = match self.ctx.two_fixnums_on_stack(&mut self.jit) {
            Some(two_fixnums) => two_fixnums,
            None => {
                // Defer compilation so we can specialize on a runtime `self`
                self.defer_compilation();
                return CodegenStatus::EndBlock;
            }
        };

        if two_fixnums {
            // Create a side-exit to fall back to the interpreter
            // Note: we generate the side-exit before popping operands from the stack
            let side_exit = self.get_side_exit(&self.ctx.clone());

            if !self.assume_bop_not_redefined(INTEGER_REDEFINED_OP_FLAG, BOP_MINUS) {
                return CodegenStatus::CantCompile;
            }

            // Check that both operands are fixnums
            self.guard_two_fixnums(side_exit);

            // Get the operands and destination from the stack
            let arg1 = self.ctx.stack_pop(1);
            let arg0 = self.ctx.stack_pop(1);

            // Subtract arg0 - arg1 and test for overflow
            let val_untag = self.asm.sub(arg0, arg1);
            self.asm.jo(side_exit);
            let val = self.asm.add(val_untag, Opnd::Imm(1));

            // Push the output on the stack
            let dst = self.ctx.stack_push(Type::Fixnum);
            self.asm.store(dst, val);

            CodegenStatus::KeepCompiling
        } else {
            // Delegate to send, call the method on the recv
            self.gen_opt_send_without_block()
        }
    }

    fn gen_opt_mult(&mut self) -> CodegenStatus {
        // Delegate to send, call the method on the recv
        self.gen_opt_send_without_block()
    }

    fn gen_opt_div(&mut self) -> CodegenStatus {
        // Delegate to send, call the method on the recv
        self.gen_opt_send_without_block()
    }

    fn gen_opt_mod(&mut self) -> CodegenStatus {
        let two_fixnums = match self.ctx.two_fixnums_on_stack(&mut self.jit) {
            Some(two_fixnums) => two_fixnums,
            None => {
                // Defer compilation so we can specialize on a runtime `self`
                self.defer_compilation();
                return CodegenStatus::EndBlock;
            }
        };

        if two_fixnums {
            // Create a side-exit to fall back to the interpreter
            // Note: we generate the side-exit before popping operands from the stack
            let side_exit = self.get_side_exit(&self.ctx.clone());

            if !self.assume_bop_not_redefined(INTEGER_REDEFINED_OP_FLAG, BOP_MOD) {
                return CodegenStatus::CantCompile;
            }

            // Check that both operands are fixnums
            self.guard_two_fixnums(side_exit);

            // Get the operands and destination from the stack
            let arg1 = self.ctx.stack_pop(1);
            let arg0 = self.ctx.stack_pop(1);

            // Check for arg0 % 0
            self.asm
                .cmp(arg1, Opnd::Imm(VALUE::fixnum_from_usize(0).as_i64()));
            self.asm.je(side_exit);

            // Call rb_fix_mod_fix(VALUE recv, VALUE obj)
            let ret = self
                .asm
                .ccall(rb_fix_mod_fix as *const u8, vec![arg0, arg1]);

            // Push the return value onto the stack
            let stack_ret = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(stack_ret, ret);

            CodegenStatus::KeepCompiling
        } else {
            // Delegate to send, call the method on the recv
            self.gen_opt_send_without_block()
        }
    }

    fn gen_opt_ltlt(&mut self) -> CodegenStatus {
        // Delegate to send, call the method on the recv
        self.gen_opt_send_without_block()
    }

    fn gen_opt_nil_p(&mut self) -> CodegenStatus {
        // Delegate to send, call the method on the recv
        self.gen_opt_send_without_block()
    }

    fn gen_opt_empty_p(&mut self) -> CodegenStatus {
        // Delegate to send, call the method on the recv
        self.gen_opt_send_without_block()
    }

    fn gen_opt_succ(&mut self) -> CodegenStatus {
        // Delegate to send, call the method on the recv
        self.gen_opt_send_without_block()
    }

    fn gen_opt_str_freeze(&mut self) -> CodegenStatus {
        if !self.assume_bop_not_redefined(STRING_REDEFINED_OP_FLAG, BOP_FREEZE) {
            return CodegenStatus::CantCompile;
        }

        let str = self.jit.get_arg(0);

        // Push the return value onto the stack
        let stack_ret = self.ctx.stack_push(Type::CString);
        self.asm.mov(stack_ret, str.into());

        CodegenStatus::KeepCompiling
    }

    fn gen_opt_str_uminus(&mut self) -> CodegenStatus {
        if !self.assume_bop_not_redefined(STRING_REDEFINED_OP_FLAG, BOP_UMINUS) {
            return CodegenStatus::CantCompile;
        }

        let str = self.jit.get_arg(0);

        // Push the return value onto the stack
        let stack_ret = self.ctx.stack_push(Type::CString);
        self.asm.mov(stack_ret, str.into());

        CodegenStatus::KeepCompiling
    }

    fn gen_opt_newarray_max(&mut self) -> CodegenStatus {
        let num = self.jit.get_arg(0).as_u32();

        // Save the PC and SP because we may allocate
        self.jit_prepare_routine_call();

        extern "C" {
            fn rb_vm_opt_newarray_max(ec: EcPtr, num: u32, elts: *const VALUE) -> VALUE;
        }

        let offset_magnitude = (SIZEOF_VALUE as u32) * num;
        let values_opnd = self.ctx.sp_opnd(-(offset_magnitude as isize));
        let values_ptr = self.asm.lea(values_opnd);

        let val_opnd = self.asm.ccall(
            rb_vm_opt_newarray_max as *const u8,
            vec![EC, num.into(), values_ptr],
        );

        self.ctx.stack_pop(num.into_usize());
        let stack_ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(stack_ret, val_opnd);

        CodegenStatus::KeepCompiling
    }

    fn gen_opt_newarray_min(&mut self) -> CodegenStatus {
        let num = self.jit.get_arg(0).as_u32();

        // Save the PC and SP because we may allocate
        self.jit_prepare_routine_call();

        extern "C" {
            fn rb_vm_opt_newarray_min(ec: EcPtr, num: u32, elts: *const VALUE) -> VALUE;
        }

        let offset_magnitude = (SIZEOF_VALUE as u32) * num;
        let values_opnd = self.ctx.sp_opnd(-(offset_magnitude as isize));
        let values_ptr = self.asm.lea(values_opnd);

        let val_opnd = self.asm.ccall(
            rb_vm_opt_newarray_min as *const u8,
            vec![EC, num.into(), values_ptr],
        );

        self.ctx.stack_pop(num.into_usize());
        let stack_ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(stack_ret, val_opnd);

        CodegenStatus::KeepCompiling
    }

    fn gen_opt_not(&mut self) -> CodegenStatus {
        self.gen_opt_send_without_block()
    }

    fn gen_opt_size(&mut self) -> CodegenStatus {
        self.gen_opt_send_without_block()
    }

    fn gen_opt_length(&mut self) -> CodegenStatus {
        self.gen_opt_send_without_block()
    }

    fn gen_opt_regexpmatch2(&mut self) -> CodegenStatus {
        self.gen_opt_send_without_block()
    }

    fn gen_opt_case_dispatch(&mut self) -> CodegenStatus {
        // Normally this instruction would lookup the key in a hash and jump to an
        // offset based on that.
        // Instead we can take the fallback case and continue with the next
        // instruction.
        // We'd hope that our jitted code will be sufficiently fast without the
        // hash lookup, at least for small hashes, but it's worth revisiting this
        // assumption in the future.
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }
        let starting_context = self.ctx.clone();

        let case_hash = self.jit.get_arg(0);
        let else_offset = self.jit.get_arg(1).as_u32();

        // Try to reorder case/else branches so that ones that are actually used come first.
        // Supporting only Fixnum for now so that the implementation can be an equality check.
        let key_opnd = self.ctx.stack_pop(1);
        let comptime_key = self.jit.peek_at_stack(&self.ctx, 0);

        // Check that all cases are fixnums to avoid having to register BOP assumptions on
        // all the types that case hashes support. This spends compile time to save memory.
        fn case_hash_all_fixnum_p(hash: VALUE) -> bool {
            let mut all_fixnum = true;
            unsafe {
                unsafe extern "C" fn per_case(
                    key: st_data_t,
                    _value: st_data_t,
                    data: st_data_t,
                ) -> c_int {
                    (if VALUE(key as usize).fixnum_p() {
                        ST_CONTINUE
                    } else {
                        (data as *mut bool).write(false);
                        ST_STOP
                    }) as c_int
                }
                rb_hash_stlike_foreach(
                    hash,
                    Some(per_case),
                    (&mut all_fixnum) as *mut _ as st_data_t,
                );
            }

            all_fixnum
        }

        if comptime_key.fixnum_p()
            && comptime_key.0 <= u32::MAX.into_usize()
            && case_hash_all_fixnum_p(case_hash)
        {
            if !self.assume_bop_not_redefined(INTEGER_REDEFINED_OP_FLAG, BOP_EQQ) {
                return CodegenStatus::CantCompile;
            }

            // Check if the key is the same value
            self.asm.cmp(key_opnd, comptime_key.into());
            let side_exit = self.get_side_exit(&starting_context);
            self.jit_chain_guard(&starting_context, JCC_JNE, CASE_WHEN_MAX_DEPTH, side_exit);

            // Get the offset for the compile-time key
            let mut offset = 0;
            unsafe { rb_hash_stlike_lookup(case_hash, comptime_key.0 as _, &mut offset) };
            let jump_offset = if offset == 0 {
                // NOTE: If we hit the else branch with various values, it could negatively impact the performance.
                else_offset
            } else {
                (offset as u32) >> 1 // FIX2LONG
            };

            // Jump to the offset of case or else
            let jump_block = BlockId {
                iseq: self.jit.iseq,
                idx: self.jit.next_insn_idx() + jump_offset,
            };
            gen_direct_jump(&mut self.jit, &self.ctx, jump_block, &mut self.asm);
            CodegenStatus::EndBlock
        } else {
            CodegenStatus::KeepCompiling // continue with === branches
        }
    }

    fn gen_branchif(&mut self) -> CodegenStatus {
        let jump_offset = self.jit.get_arg(0).as_i32();

        // Check for interrupts, but only on backward branches that may create loops
        if jump_offset < 0 {
            let side_exit = self.get_side_exit(&self.ctx.clone());
            gen_check_ints(&mut self.asm, side_exit);
        }

        // Get the branch target instruction offsets
        let next_idx = self.jit.next_insn_idx();
        let jump_idx = (next_idx as i32) + jump_offset;
        let next_block = BlockId {
            iseq: self.jit.iseq,
            idx: next_idx,
        };
        let jump_block = BlockId {
            iseq: self.jit.iseq,
            idx: jump_idx as u32,
        };

        // Test if any bit (outside of the Qnil bit) is on
        // See RB_TEST()
        let val_type = self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0));
        let val_opnd = self.ctx.stack_pop(1);

        if let Some(result) = val_type.known_truthy() {
            let target = if result { jump_block } else { next_block };
            gen_direct_jump(&mut self.jit, &self.ctx, target, &mut self.asm);
        } else {
            self.asm.test(val_opnd, Opnd::Imm(!Qnil.as_i64()));

            // Generate the branch instructions
            gen_branch(
                self,
                jump_block,
                &self.ctx.clone(),
                Some(next_block),
                Some(&self.ctx.clone()),
                BranchGenFn::BranchIf(BranchShape::Default),
            );
        }

        CodegenStatus::EndBlock
    }

    fn gen_branchunless(&mut self) -> CodegenStatus {
        let jump_offset = self.jit.get_arg(0).as_i32();

        // Check for interrupts, but only on backward branches that may create loops
        if jump_offset < 0 {
            let side_exit = self.get_side_exit(&self.ctx.clone());
            gen_check_ints(&mut self.asm, side_exit);
        }

        // Get the branch target instruction offsets
        let next_idx = self.jit.next_insn_idx() as i32;
        let jump_idx = next_idx + jump_offset;
        let next_block = BlockId {
            iseq: self.jit.iseq,
            idx: next_idx.try_into().unwrap(),
        };
        let jump_block = BlockId {
            iseq: self.jit.iseq,
            idx: jump_idx.try_into().unwrap(),
        };

        let val_type = self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0));
        let val_opnd = self.ctx.stack_pop(1);

        if let Some(result) = val_type.known_truthy() {
            let target = if result { next_block } else { jump_block };
            gen_direct_jump(&mut self.jit, &self.ctx, target, &mut self.asm);
        } else {
            // Test if any bit (outside of the Qnil bit) is on
            // See RB_TEST()
            let not_qnil = !Qnil.as_i64();
            self.asm.test(val_opnd, not_qnil.into());

            // Generate the branch instructions
            gen_branch(
                self,
                jump_block,
                &self.ctx.clone(),
                Some(next_block),
                Some(&self.ctx.clone()),
                BranchGenFn::BranchUnless(BranchShape::Default),
            );
        }

        CodegenStatus::EndBlock
    }

    fn gen_branchnil(&mut self) -> CodegenStatus {
        let jump_offset = self.jit.get_arg(0).as_i32();

        // Check for interrupts, but only on backward branches that may create loops
        if jump_offset < 0 {
            let side_exit = self.get_side_exit(&self.ctx.clone());
            gen_check_ints(&mut self.asm, side_exit);
        }

        // Get the branch target instruction offsets
        let next_idx = self.jit.next_insn_idx() as i32;
        let jump_idx = next_idx + jump_offset;
        let next_block = BlockId {
            iseq: self.jit.iseq,
            idx: next_idx.try_into().unwrap(),
        };
        let jump_block = BlockId {
            iseq: self.jit.iseq,
            idx: jump_idx.try_into().unwrap(),
        };

        let val_type = self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0));
        let val_opnd = self.ctx.stack_pop(1);

        if let Some(result) = val_type.known_nil() {
            let target = if result { jump_block } else { next_block };
            gen_direct_jump(&mut self.jit, &self.ctx, target, &mut self.asm);
        } else {
            // Test if the value is Qnil
            self.asm.cmp(val_opnd, Opnd::UImm(Qnil.into()));
            // Generate the branch instructions
            gen_branch(
                self,
                jump_block,
                &self.ctx.clone(),
                Some(next_block),
                Some(&self.ctx.clone()),
                BranchGenFn::BranchNil(BranchShape::Default),
            );
        }

        CodegenStatus::EndBlock
    }

    fn gen_jump(&mut self) -> CodegenStatus {
        let jump_offset = self.jit.get_arg(0).as_i32();

        // Check for interrupts, but only on backward branches that may create loops
        if jump_offset < 0 {
            let side_exit = self.get_side_exit(&self.ctx.clone());
            gen_check_ints(&mut self.asm, side_exit);
        }

        // Get the branch target instruction offsets
        let jump_idx = (self.jit.next_insn_idx() as i32) + jump_offset;
        let jump_block = BlockId {
            iseq: self.jit.iseq,
            idx: jump_idx as u32,
        };

        // Generate the jump instruction
        gen_direct_jump(&mut self.jit, &self.ctx, jump_block, &mut self.asm);

        CodegenStatus::EndBlock
    }

    /// Guard that self or a stack operand has the same class as `known_klass`, using
    /// `sample_instance` to speculate about the shape of the runtime value.
    /// FIXNUM and on-heap integers are treated as if they have distinct classes, and
    /// the guard generated for one will fail for the other.
    ///
    /// Recompile as contingency if possible, or take side exit a last resort.
    fn jit_guard_known_klass(
        &mut self,
        known_klass: VALUE,
        obj_opnd: Opnd,
        insn_opnd: YARVOpnd,
        sample_instance: VALUE,
        max_chain_depth: i32,
        side_exit: Target,
    ) {
        let val_type = self.ctx.get_opnd_type(insn_opnd);

        if val_type.known_class() == Some(known_klass) {
            // We already know from type information that this is a match
            return;
        }

        if unsafe { known_klass == rb_cNilClass } {
            assert!(!val_type.is_heap());
            assert!(val_type.is_unknown());

            self.asm.comment("guard object is nil");
            self.asm.cmp(obj_opnd, Qnil.into());
            self.jit_chain_guard(&self.ctx.clone(), JCC_JNE, max_chain_depth, side_exit);

            self.ctx.upgrade_opnd_type(insn_opnd, Type::Nil);
        } else if unsafe { known_klass == rb_cTrueClass } {
            assert!(!val_type.is_heap());
            assert!(val_type.is_unknown());

            self.asm.comment("guard object is true");
            self.asm.cmp(obj_opnd, Qtrue.into());
            self.jit_chain_guard(&self.ctx.clone(), JCC_JNE, max_chain_depth, side_exit);

            self.ctx.upgrade_opnd_type(insn_opnd, Type::True);
        } else if unsafe { known_klass == rb_cFalseClass } {
            assert!(!val_type.is_heap());
            assert!(val_type.is_unknown());

            self.asm.comment("guard object is false");
            assert!(Qfalse.as_i32() == 0);
            self.asm.test(obj_opnd, obj_opnd);
            self.jit_chain_guard(&self.ctx.clone(), JCC_JNZ, max_chain_depth, side_exit);

            self.ctx.upgrade_opnd_type(insn_opnd, Type::False);
        } else if unsafe { known_klass == rb_cInteger } && sample_instance.fixnum_p() {
            // We will guard fixnum and bignum as though they were separate classes
            // BIGNUM can be handled by the general else case below
            assert!(val_type.is_unknown());

            self.asm.comment("guard object is fixnum");
            self.asm.test(obj_opnd, Opnd::Imm(RUBY_FIXNUM_FLAG as i64));
            self.jit_chain_guard(&self.ctx.clone(), JCC_JZ, max_chain_depth, side_exit);
            self.ctx.upgrade_opnd_type(insn_opnd, Type::Fixnum);
        } else if unsafe { known_klass == rb_cSymbol } && sample_instance.static_sym_p() {
            assert!(!val_type.is_heap());
            // We will guard STATIC vs DYNAMIC as though they were separate classes
            // DYNAMIC symbols can be handled by the general else case below
            if val_type != Type::ImmSymbol || !val_type.is_imm() {
                assert!(val_type.is_unknown());

                self.asm.comment("guard object is static symbol");
                const _: () = if RUBY_SPECIAL_SHIFT != 8 {
                    panic!("RUBY_SPECIAL_SHIFT != 8");
                };

                self.asm.cmp(
                    obj_opnd.with_num_bits(8).unwrap(),
                    Opnd::UImm(RUBY_SYMBOL_FLAG as u64),
                );
                self.jit_chain_guard(&self.ctx.clone(), JCC_JNE, max_chain_depth, side_exit);
                self.ctx.upgrade_opnd_type(insn_opnd, Type::ImmSymbol);
            }
        } else if unsafe { known_klass == rb_cFloat } && sample_instance.flonum_p() {
            assert!(!val_type.is_heap());
            if val_type != Type::Flonum || !val_type.is_imm() {
                assert!(val_type.is_unknown());

                // We will guard flonum vs heap float as though they were separate classes
                self.asm.comment("guard object is flonum");
                let flag_bits = self.asm.and(obj_opnd, Opnd::UImm(RUBY_FLONUM_MASK as u64));
                self.asm.cmp(flag_bits, Opnd::UImm(RUBY_FLONUM_FLAG as u64));
                self.jit_chain_guard(&self.ctx.clone(), JCC_JNE, max_chain_depth, side_exit);
                self.ctx.upgrade_opnd_type(insn_opnd, Type::Flonum);
            }
        } else if unsafe {
            FL_TEST(known_klass, VALUE(RUBY_FL_SINGLETON as usize)) != VALUE(0)
                && sample_instance == rb_class_attached_object(known_klass)
        } {
            // Singleton classes are attached to one specific object, so we can
            // avoid one memory access (and potentially the is_heap check) by
            // looking for the expected object directly.
            // Note that in case the sample instance has a singleton class that
            // doesn't attach to the sample instance, it means the sample instance
            // has an empty singleton class that hasn't been materialized yet. In
            // this case, comparing against the sample instance doesn't guarantee
            // that its singleton class is empty, so we can't avoid the memory
            // access. As an example, `Object.new.singleton_class` is an object in
            // this situation.
            self.asm.comment("guard known object with singleton class");
            self.asm.cmp(obj_opnd, sample_instance.into());
            self.jit_chain_guard(&self.ctx.clone(), JCC_JNE, max_chain_depth, side_exit);
        } else if val_type == Type::CString && unsafe { known_klass == rb_cString } {
            // guard elided because the context says we've already checked
            unsafe {
                assert_eq!(
                    sample_instance.class_of(),
                    rb_cString,
                    "context says class is exactly ::String"
                )
            };
        } else {
            assert!(!val_type.is_imm());

            // Check that the receiver is a heap object
            // Note: if we get here, the class doesn't have immediate instances.
            if !val_type.is_heap() {
                self.asm.comment("guard not immediate");
                self.asm.test(obj_opnd, (RUBY_IMMEDIATE_MASK as u64).into());
                self.jit_chain_guard(&self.ctx.clone(), JCC_JNZ, max_chain_depth, side_exit);
                self.asm.cmp(obj_opnd, Qfalse.into());
                self.jit_chain_guard(&self.ctx.clone(), JCC_JE, max_chain_depth, side_exit);

                self.ctx.upgrade_opnd_type(insn_opnd, Type::UnknownHeap);
            }

            // If obj_opnd isn't already a register, load it.
            let obj_opnd = match obj_opnd {
                Opnd::Reg(_) => obj_opnd,
                _ => self.asm.load(obj_opnd),
            };
            let klass_opnd = Opnd::mem(64, obj_opnd, RUBY_OFFSET_RBASIC_KLASS);

            // Bail if receiver class is different from known_klass
            // TODO: self.jit_mov_gc_ptr keeps a strong reference, which leaks the class.
            self.asm.comment("guard known class");
            self.asm.cmp(klass_opnd, known_klass.into());
            self.jit_chain_guard(&self.ctx.clone(), JCC_JNE, max_chain_depth, side_exit);

            if known_klass == unsafe { rb_cString } {
                self.ctx.upgrade_opnd_type(insn_opnd, Type::CString);
            } else if known_klass == unsafe { rb_cArray } {
                self.ctx.upgrade_opnd_type(insn_opnd, Type::CArray);
            }
        }
    }

    // Generate ancestry guard for protected callee.
    // Calls to protected callees only go through when self.is_a?(klass_that_defines_the_callee).
    fn jit_protected_callee_ancestry_guard(
        &mut self,
        cme: *const rb_callable_method_entry_t,
        side_exit: Target,
    ) {
        // See vm_call_method().
        let def_class = unsafe { (*cme).defined_class };
        // Note: PC isn't written to current control frame as rb_is_kind_of() shouldn't raise.
        // VALUE rb_obj_is_kind_of(VALUE obj, VALUE klass);

        let val = self.asm.ccall(
            rb_obj_is_kind_of as *mut u8,
            vec![Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SELF), def_class.into()],
        );
        self.asm.test(val, val);
        let exit = counted_exit!(self.get_ocb(), side_exit, send_se_protected_check_failed);
        self.asm.jz(exit)
    }

    fn gen_opt_send_without_block(&mut self) -> CodegenStatus {
        let cd = self.jit.get_arg(0).as_ptr();
        self.gen_send_general(cd, None)
    }

    /// jit_save_pc() + gen_save_sp(). Should be used before calling a routine that
    /// could:
    ///  - Perform GC allocation
    ///  - Take the VM lock through RB_VM_LOCK_ENTER()
    ///  - Perform Ruby method call
    fn jit_prepare_routine_call(&mut self) {
        self.jit.record_boundary_patch_point = true;
        jit_save_pc(&self.jit, &mut self.asm);
        gen_save_sp(&mut self.asm, &mut self.ctx);

        // In case the routine calls Ruby methods, it can set local variables
        // through Kernel#binding and other means.
        self.ctx.clear_local_types();
    }

    // Codegen performing a similar (but not identical) function to vm_push_frame
    //
    // This will generate the code to:
    //   * initialize locals to Qnil
    //   * push the environment (cme, block handler, frame type)
    //   * push a new CFP
    //   * save the new CFP to ec->cfp
    //
    // Notes:
    //   * Provided sp should point to the new frame's sp, immediately following locals and the environment
    //   * At entry, CFP points to the caller (not callee) frame
    //   * At exit, ec->cfp is updated to the pushed CFP
    //   * CFP and SP registers are updated only if set_sp_cfp is set
    //   * Stack overflow is not checked (should be done by the caller)
    //   * Interrupts are not checked (should be done by the caller)
    fn gen_push_frame(
        &mut self,
        set_sp_cfp: bool, // if true CFP and SP will be switched to the callee
        frame: ControlFrame,
    ) {
        assert!(frame.local_size >= 0);

        let sp = frame.sp;

        self.asm.comment("push cme, specval, frame type");

        // Write method entry at sp[-3]
        // sp[-3] = me;
        // Use compile time cme. It's assumed to be valid because we are notified when
        // any cme we depend on become outdated. See yjit_method_lookup_change().
        self.asm.store(
            Opnd::mem(64, sp, SIZEOF_VALUE_I32 * -3),
            VALUE::from(frame.cme).into(),
        );

        // Write special value at sp[-2]. It's either a block handler or a pointer to
        // the outer environment depending on the frame type.
        // sp[-2] = specval;
        let specval: Opnd = match frame.specval {
            SpecVal::None => VM_BLOCK_HANDLER_NONE.into(),
            SpecVal::BlockISeq(block_iseq) => {
                // Change cfp->block_code in the current frame. See vm_caller_setup_arg_block().
                // VM_CFP_TO_CAPTURED_BLOCK does &cfp->self, rb_captured_block->code.iseq aliases
                // with cfp->block_code.
                self.asm.store(
                    Opnd::mem(64, CFP, RUBY_OFFSET_CFP_BLOCK_CODE),
                    VALUE::from(block_iseq).into(),
                );

                let cfp_self = self.asm.lea(Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SELF));
                self.asm.or(cfp_self, Opnd::Imm(1))
            }
            SpecVal::BlockParamProxy => {
                let ep_opnd = self.gen_get_lep();
                let block_handler = self.asm.load(Opnd::mem(
                    64,
                    ep_opnd,
                    SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_SPECVAL,
                ));

                self.asm.store(
                    Opnd::mem(64, CFP, RUBY_OFFSET_CFP_BLOCK_CODE),
                    block_handler,
                );

                block_handler
            }
            SpecVal::PrevEP(prev_ep) => {
                let tagged_prev_ep = (prev_ep as usize) | 1;
                VALUE(tagged_prev_ep).into()
            }
            SpecVal::PrevEPOpnd(ep_opnd) => self.asm.or(ep_opnd, 1.into()),
        };
        self.asm
            .store(Opnd::mem(64, sp, SIZEOF_VALUE_I32 * -2), specval);

        // Write env flags at sp[-1]
        // sp[-1] = frame_type;
        self.asm.store(
            Opnd::mem(64, sp, -SIZEOF_VALUE_I32),
            frame.frame_type.into(),
        );

        // Allocate a new CFP (ec->cfp--)
        fn cfp_opnd(offset: i32) -> Opnd {
            Opnd::mem(64, CFP, offset - (RUBY_SIZEOF_CONTROL_FRAME as i32))
        }

        // Setup the new frame
        // *cfp = (const struct rb_control_frame_struct) {
        //    .pc         = <unset for iseq, 0 for cfunc>,
        //    .sp         = sp,
        //    .iseq       = <iseq for iseq, 0 for cfunc>,
        //    .self       = recv,
        //    .ep         = <sp - 1>,
        //    .block_code = 0,
        //    .__bp__     = sp,
        // };
        self.asm.comment("push callee control frame");

        // For an iseq call PC may be None, in which case we will not set PC and will allow jitted code
        // to set it as necessary.
        if let Some(pc) = frame.pc {
            self.asm.mov(cfp_opnd(RUBY_OFFSET_CFP_PC), pc.into());
        };
        self.asm.mov(cfp_opnd(RUBY_OFFSET_CFP_BP), sp);
        self.asm.mov(cfp_opnd(RUBY_OFFSET_CFP_SP), sp);
        let iseq: Opnd = if let Some(iseq) = frame.iseq {
            VALUE::from(iseq).into()
        } else {
            0.into()
        };
        self.asm.mov(cfp_opnd(RUBY_OFFSET_CFP_ISEQ), iseq);
        self.asm.mov(cfp_opnd(RUBY_OFFSET_CFP_SELF), frame.recv);
        self.asm.mov(cfp_opnd(RUBY_OFFSET_CFP_BLOCK_CODE), 0.into());

        // This Qnil fill snippet potentially requires 2 more registers on Arm, one for Qnil and
        // another for calculating the address in case there are a lot of local variables. So doing
        // this after releasing the register for specval and the receiver to avoid register spill.
        let num_locals = frame.local_size;
        if num_locals > 0 {
            self.asm.comment("initialize locals");

            // Initialize local variables to Qnil
            for i in 0..num_locals {
                let offs = SIZEOF_VALUE_I32 * (i - num_locals - 3);
                self.asm.store(Opnd::mem(64, sp, offs), Qnil.into());
            }
        }

        if set_sp_cfp {
            // Saving SP before calculating ep avoids a dependency on a register
            // However this must be done after referencing frame.recv, which may be SP-relative
            self.asm.mov(SP, sp);
        }
        let ep = self.asm.sub(sp, SIZEOF_VALUE.into());
        self.asm.mov(cfp_opnd(RUBY_OFFSET_CFP_EP), ep);

        self.asm.comment("switch to new CFP");
        let new_cfp = self.asm.lea(cfp_opnd(0));
        if set_sp_cfp {
            self.asm.mov(CFP, new_cfp);
            self.asm.store(Opnd::mem(64, EC, RUBY_OFFSET_EC_CFP), CFP);
        } else {
            self.asm
                .store(Opnd::mem(64, EC, RUBY_OFFSET_EC_CFP), new_cfp);
        }
    }

    fn gen_send_cfunc(
        &mut self,
        ci: *const rb_callinfo,
        cme: *const rb_callable_method_entry_t,
        block: Option<IseqPtr>,
        recv_known_klass: *const VALUE,
        call_info: CallInfo,
        argc: i32,
    ) -> CodegenStatus {
        let cfunc = unsafe { get_cme_def_body_cfunc(cme) };
        let cfunc_argc = unsafe { get_mct_argc(cfunc) };
        let mut argc = argc;

        // Create a side-exit to fall back to the interpreter
        let side_exit = self.get_side_exit(&self.ctx.clone());

        // If the function expects a Ruby array of arguments
        if cfunc_argc < 0 && cfunc_argc != -1 {
            gen_counter_incr!(&mut self.asm, send_cfunc_ruby_array_varg);
            return CodegenStatus::CantCompile;
        }

        // We aren't handling a vararg cfuncs with splat currently.
        if call_info.flags.is_splat() && cfunc_argc == -1 {
            gen_counter_incr!(&mut self.asm, send_args_splat_cfunc_var_args);
            return CodegenStatus::CantCompile;
        }

        if call_info.flags.is_splat() && call_info.flags.is_zsuper() {
            // zsuper methods are super calls without any arguments.
            // They are also marked as splat, but don't actually have an array
            // they pull arguments from, instead we need to change to call
            // a different method with the current stack.
            gen_counter_incr!(&mut self.asm, send_args_splat_cfunc_zuper);
            return CodegenStatus::CantCompile;
        }

        // In order to handle backwards compatibility between ruby 3 and 2
        // ruby2_keywords was introduced. It is called only on methods
        // with splat and changes they way they handle them.
        // We are just going to not compile these.
        // https://docs.ruby-lang.org/en/3.2/Module.html#method-i-ruby2_keywords
        if unsafe { get_iseq_flags_ruby2_keywords(self.jit.iseq) && call_info.flags.is_splat() } {
            gen_counter_incr!(&mut self.asm, send_args_splat_cfunc_ruby2_keywords);
            return CodegenStatus::CantCompile;
        }

        let kw_arg = unsafe { vm_ci_kwarg(ci) };
        let kw_arg_num = if kw_arg.is_null() {
            0
        } else {
            unsafe { get_cikw_keyword_len(kw_arg) }
        };

        if kw_arg_num != 0 && call_info.flags.is_splat() {
            gen_counter_incr!(&mut self.asm, send_cfunc_splat_with_kw);
            return CodegenStatus::CantCompile;
        }

        if c_method_tracing_currently_enabled(&self.jit) {
            // Don't JIT if tracing c_call or c_return
            gen_counter_incr!(&mut self.asm, send_cfunc_tracing);
            return CodegenStatus::CantCompile;
        }

        // Delegate to codegen for C methods if we have it.
        if kw_arg.is_null() && !call_info.flags.is_opt_send() {
            let codegen_p = lookup_cfunc_codegen(unsafe { (*cme).def });
            if let Some(known_cfunc_codegen) = codegen_p {
                if known_cfunc_codegen(self, ci, cme, block, argc, recv_known_klass) {
                    // cfunc codegen generated code. Terminate the block so
                    // there isn't multiple calls in the same block.
                    self.jump_to_next_insn();
                    return CodegenStatus::EndBlock;
                }
            }
        }

        // Check for interrupts
        gen_check_ints(&mut self.asm, side_exit);

        // Stack overflow check
        // #define CHECK_VM_STACK_OVERFLOW0(cfp, sp, margin)
        // REG_CFP <= REG_SP + 4 * SIZEOF_VALUE + sizeof(rb_control_frame_t)
        self.asm.comment("stack overflow check");
        let stack_limit = self.asm.lea(
            self.ctx
                .sp_opnd((SIZEOF_VALUE * 4 + 2 * RUBY_SIZEOF_CONTROL_FRAME) as isize),
        );
        self.asm.cmp(CFP, stack_limit);
        let exit = counted_exit!(self.get_ocb(), side_exit, send_se_cf_overflow);
        self.asm.jbe(exit);

        // Number of args which will be passed through to the callee
        // This is adjusted by the kwargs being combined into a hash.
        let mut passed_argc = if kw_arg.is_null() {
            argc
        } else {
            argc - kw_arg_num + 1
        };

        // If the argument count doesn't match
        if cfunc_argc >= 0 && cfunc_argc != passed_argc && !call_info.flags.is_splat() {
            gen_counter_incr!(&mut self.asm, send_cfunc_argc_mismatch);
            return CodegenStatus::CantCompile;
        }

        // Don't JIT functions that need C stack arguments for now
        if cfunc_argc >= 0 && passed_argc + 1 > (C_ARG_OPNDS.len() as i32) {
            gen_counter_incr!(&mut self.asm, send_cfunc_toomany_args);
            return CodegenStatus::CantCompile;
        }

        let block_arg = call_info.flags.is_block_arg();
        let block_arg_type = if block_arg {
            Some(self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)))
        } else {
            None
        };

        match block_arg_type {
            Some(Type::Nil | Type::BlockParamProxy) => {
                // We'll handle this later
            }
            None => {
                // Nothing to do
            }
            _ => {
                gen_counter_incr!(&mut self.asm, send_block_arg);
                return CodegenStatus::CantCompile;
            }
        }

        match block_arg_type {
            Some(Type::Nil) => {
                // We have a nil block arg, so let's pop it off the args
                self.ctx.stack_pop(1);
            }
            Some(Type::BlockParamProxy) => {
                // We don't need the actual stack value
                self.ctx.stack_pop(1);
            }
            None => {
                // Nothing to do
            }
            _ => {
                unreachable!("Block arg type should be None or nil or block param proxy");
            }
        }

        // push_splat_args does stack manipulation so we can no longer side exit
        if call_info.flags.is_splat() {
            assert!(cfunc_argc >= 0);
            let required_args: u32 = (cfunc_argc as u32).saturating_sub(argc as u32 - 1);
            // + 1 because we pass self
            if required_args + 1 >= C_ARG_OPNDS.len() as u32 {
                gen_counter_incr!(&mut self.asm, send_cfunc_toomany_args);
                return CodegenStatus::CantCompile;
            }

            // We are going to assume that the splat fills
            // all the remaining arguments. So the number of args
            // should just equal the number of args the cfunc takes.
            // In the generated code we test if this is true
            // and if not side exit.
            argc = cfunc_argc;
            passed_argc = argc;
            self.push_splat_args(required_args, side_exit)
        }

        // This is a .send call and we need to adjust the stack
        if call_info.flags.is_opt_send() {
            self.handle_opt_send_shift_stack(argc);
        }

        // Points to the receiver operand on the stack
        let recv = self.ctx.stack_opnd(argc);

        // Store incremented PC into current control frame in case callee raises.
        jit_save_pc(&self.jit, &mut self.asm);

        // Increment the stack pointer by 3 (in the callee)
        // sp += 3
        let sp = self.asm.lea(self.ctx.sp_opnd((SIZEOF_VALUE as isize) * 3));

        let specval = if block_arg_type == Some(Type::BlockParamProxy) {
            SpecVal::BlockParamProxy
        } else if let Some(block_iseq) = block {
            SpecVal::BlockISeq(block_iseq)
        } else {
            SpecVal::None
        };

        let mut frame_type = VM_FRAME_MAGIC_CFUNC | VM_FRAME_FLAG_CFRAME | VM_ENV_FLAG_LOCAL;
        if !kw_arg.is_null() {
            frame_type |= VM_FRAME_FLAG_CFRAME_KW
        }

        self.gen_push_frame(
            false,
            ControlFrame {
                frame_type,
                specval,
                cme,
                recv,
                sp,
                pc: Some(0),
                iseq: None,
                local_size: 0,
            },
        );

        if !kw_arg.is_null() {
            // Build a hash from all kwargs passed
            self.asm.comment("build_kwhash");
            let imemo_ci = VALUE(ci as usize);
            assert_ne!(
                0,
                unsafe { rb_IMEMO_TYPE_P(imemo_ci, imemo_callinfo) },
                "we assume all callinfos with kwargs are on the GC heap"
            );
            let sp = self.asm.lea(self.ctx.sp_opnd(0));
            let kwargs = self
                .asm
                .ccall(build_kwhash as *const u8, vec![imemo_ci.into(), sp]);

            // Replace the stack location at the start of kwargs with the new hash
            let stack_opnd = self.ctx.stack_opnd(argc - passed_argc);
            self.asm.mov(stack_opnd, kwargs);
        }

        // Copy SP because REG_SP will get overwritten
        let sp = self.asm.lea(self.ctx.sp_opnd(0));

        // Pop the C function arguments from the stack (in the caller)
        self.ctx.stack_pop((argc + 1).try_into().unwrap());

        // Write interpreter SP into CFP.
        // Needed in case the callee yields to the block.
        gen_save_sp(&mut self.asm, &mut self.ctx);

        // Non-variadic method
        let args = if cfunc_argc >= 0 {
            // Copy the arguments from the stack to the C argument registers
            // self is the 0th argument and is at index argc from the stack top
            (0..=passed_argc)
                .map(|i| Opnd::mem(64, sp, -(argc + 1 - i) * SIZEOF_VALUE_I32))
                .collect()
        }
        // Variadic method
        else if cfunc_argc == -1 {
            // The method gets a pointer to the first argument
            // rb_f_puts(int argc, VALUE *argv, VALUE recv)
            vec![
                Opnd::Imm(passed_argc.into()),
                self.asm.lea(Opnd::mem(64, sp, -(argc) * SIZEOF_VALUE_I32)),
                Opnd::mem(64, sp, -(argc + 1) * SIZEOF_VALUE_I32),
            ]
        } else {
            panic!("unexpected cfunc_args: {}", cfunc_argc)
        };

        // Call the C function
        // VALUE ret = (cfunc->func)(recv, argv[0], argv[1]);
        // cfunc comes from compile-time cme->def, which we assume to be stable.
        // Invalidation logic is in yjit_method_lookup_change()
        self.asm.comment("call C function");
        let ret = self.asm.ccall(unsafe { get_mct_func(cfunc) }.cast(), args);

        // Record code position for TracePoint patching. See full_cfunc_return().
        record_global_inval_patch(
            &mut self.asm,
            CodegenGlobals::get_outline_full_cfunc_return_pos(),
        );

        // Push the return value on the Ruby stack
        let stack_ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(stack_ret, ret);

        // Pop the stack frame (ec->cfp++)
        // Instead of recalculating, we can reuse the previous CFP, which is stored in a callee-saved
        // register
        let ec_cfp_opnd = Opnd::mem(64, EC, RUBY_OFFSET_EC_CFP);
        self.asm.store(ec_cfp_opnd, CFP);

        // cfunc calls may corrupt types
        self.ctx.clear_local_types();

        // Note: the return block of gen_send_iseq() has ctx->sp_offset == 1
        // which allows for sharing the same successor.

        // Jump (fall through) to the call continuation block
        // We do this to end the current block after the call
        self.jump_to_next_insn();
        CodegenStatus::EndBlock
    }

    // Generate RARRAY_CONST_PTR_TRANSIENT (part of RARRAY_AREF)
    fn get_array_ptr(&mut self, array_reg: Opnd) -> Opnd {
        self.asm.comment("get array pointer for embedded or heap");

        let flags_opnd = Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RBASIC_FLAGS);
        self.asm.test(flags_opnd, (RARRAY_EMBED_FLAG as u64).into());
        let heap_ptr_opnd = Opnd::mem(usize::BITS as u8, array_reg, RUBY_OFFSET_RARRAY_AS_HEAP_PTR);
        // Load the address of the embedded array
        // (struct RArray *)(obj)->as.ary
        let ary_opnd = self
            .asm
            .lea(Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RARRAY_AS_ARY));
        self.asm.csel_nz(ary_opnd, heap_ptr_opnd)
    }

    /// Pushes arguments from an array to the stack that are passed with a splat (i.e. *args)
    /// It optimistically compiles to a static size that is the exact number of arguments
    /// needed for the function.
    fn push_splat_args(&mut self, required_args: u32, side_exit: Target) {
        self.asm.comment("push_splat_args");

        let array_opnd = self.ctx.stack_opnd(0);
        let array_reg = self.asm.load(array_opnd);

        let exit = counted_exit!(self.get_ocb(), side_exit, send_splat_not_array);
        self.guard_object_is_array(array_reg, array_opnd.into(), exit);

        self.asm.comment("Get array length for embedded or heap");

        // Pull out the embed flag to check if it's an embedded array.
        let flags_opnd = Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RBASIC_FLAGS);

        // Get the length of the array
        let emb_len_opnd = self
            .asm
            .and(flags_opnd, (RARRAY_EMBED_LEN_MASK as u64).into());
        let emb_len_opnd = self
            .asm
            .rshift(emb_len_opnd, (RARRAY_EMBED_LEN_SHIFT as u64).into());

        // Conditionally move the length of the heap array
        let flags_opnd = Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RBASIC_FLAGS);
        self.asm.test(flags_opnd, (RARRAY_EMBED_FLAG as u64).into());

        // Need to repeat this here to deal with register allocation
        let array_opnd = self.ctx.stack_opnd(0);
        let array_reg = self.asm.load(array_opnd);

        let array_len_opnd = Opnd::mem(
            std::os::raw::c_long::BITS as u8,
            array_reg,
            RUBY_OFFSET_RARRAY_AS_HEAP_LEN,
        );
        let array_len_opnd = self.asm.csel_nz(emb_len_opnd, array_len_opnd);

        self.asm
            .comment("Side exit if length doesn't not equal remaining args");
        self.asm.cmp(array_len_opnd, required_args.into());
        let exit = counted_exit!(self.get_ocb(), side_exit, send_splatarray_length_not_equal);
        self.asm.jne(exit);

        self.asm
            .comment("Check last argument is not ruby2keyword hash");

        // Need to repeat this here to deal with register allocation
        let array_reg = self.asm.load(self.ctx.stack_opnd(0));

        let ary_opnd = self.get_array_ptr(array_reg);

        let last_array_value = self.asm.load(Opnd::mem(
            64,
            ary_opnd,
            (required_args as i32 - 1) * (SIZEOF_VALUE as i32),
        ));

        let exit = counted_exit!(
            self.get_ocb(),
            side_exit,
            send_splatarray_last_ruby_2_keywords
        );
        self.guard_object_is_not_ruby2_keyword_hash(last_array_value, exit);

        self.asm.comment("Push arguments from array");
        let array_opnd = self.ctx.stack_pop(1);

        if required_args > 0 {
            // Load the address of the embedded array
            // (struct RArray *)(obj)->as.ary
            let array_reg = self.asm.load(array_opnd);

            // Conditionally load the address of the heap array
            // (struct RArray *)(obj)->as.heap.ptr
            let flags_opnd = Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RBASIC_FLAGS);
            self.asm
                .test(flags_opnd, Opnd::UImm(RARRAY_EMBED_FLAG as u64));
            let heap_ptr_opnd =
                Opnd::mem(usize::BITS as u8, array_reg, RUBY_OFFSET_RARRAY_AS_HEAP_PTR);
            // Load the address of the embedded array
            // (struct RArray *)(obj)->as.ary
            let ary_opnd =
                self.asm
                    .lea(Opnd::mem(VALUE_BITS, array_reg, RUBY_OFFSET_RARRAY_AS_ARY));
            let ary_opnd = self.asm.csel_nz(ary_opnd, heap_ptr_opnd);

            for i in 0..required_args {
                let top = self.ctx.stack_push(Type::Unknown);
                self.asm
                    .mov(top, Opnd::mem(64, ary_opnd, i as i32 * SIZEOF_VALUE_I32));
            }

            self.asm.comment("end push_each");
        }
    }

    fn gen_send_bmethod(
        &mut self,
        cme: *const rb_callable_method_entry_t,
        block: Option<IseqPtr>,
        call_info: CallInfo,
        argc: i32,
    ) -> CodegenStatus {
        let procv = unsafe { rb_get_def_bmethod_proc((*cme).def) };

        let proc = unsafe { rb_yjit_get_proc_ptr(procv) };
        let proc_block = unsafe { &(*proc).block };

        if proc_block.type_ != block_type_iseq {
            return CodegenStatus::CantCompile;
        }

        let capture = unsafe { proc_block.as_.captured.as_ref() };
        let iseq = unsafe { *capture.code.iseq.as_ref() };

        // Optimize for single ractor mode and avoid runtime check for
        // "defined with an un-shareable Proc in a different Ractor"
        if !assume_single_ractor_mode(self) {
            gen_counter_incr!(&mut self.asm, send_bmethod_ractor);
            return CodegenStatus::CantCompile;
        }

        // Passing a block to a block needs logic different from passing
        // a block to a method and sometimes requires allocation. Bail for now.
        if block.is_some() {
            gen_counter_incr!(&mut self.asm, send_bmethod_block_arg);
            return CodegenStatus::CantCompile;
        }

        let frame_type = VM_FRAME_MAGIC_BLOCK | VM_FRAME_FLAG_BMETHOD | VM_FRAME_FLAG_LAMBDA;
        self.gen_send_iseq(
            iseq,
            frame_type,
            Some(capture.ep),
            cme,
            block,
            call_info,
            argc,
            None,
        )
    }

    fn gen_send_iseq(
        &mut self,
        iseq: *const rb_iseq_t,
        frame_type: u32,
        prev_ep: Option<*const VALUE>,
        cme: *const rb_callable_method_entry_t,
        block: Option<IseqPtr>,
        call_info: CallInfo,
        argc: i32,
        captured_opnd: Option<Opnd>,
    ) -> CodegenStatus {
        let mut argc = argc;

        // Create a side-exit to fall back to the interpreter
        let side_exit = self.get_side_exit(&self.ctx.clone());

        // When you have keyword arguments, there is an extra object that gets
        // placed on the stack the represents a bitmap of the keywords that were not
        // specified at the call site. We need to keep track of the fact that this
        // value is present on the stack in order to properly set up the callee's
        // stack pointer.
        let doing_kw_call = unsafe { get_iseq_flags_has_kw(iseq) };
        let supplying_kws = call_info.flags.is_kw_arg();

        if call_info.flags.is_tail_call() {
            // We can't handle tailcalls
            gen_counter_incr!(&mut self.asm, send_iseq_tailcall);
            return CodegenStatus::CantCompile;
        }

        // No support for callees with these parameters yet as they require allocation
        // or complex handling.
        if unsafe { get_iseq_flags_has_post(iseq) } {
            gen_counter_incr!(&mut self.asm, send_iseq_has_post);
            return CodegenStatus::CantCompile;
        }
        if unsafe { get_iseq_flags_has_kwrest(iseq) } {
            gen_counter_incr!(&mut self.asm, send_iseq_has_kwrest);
            return CodegenStatus::CantCompile;
        }

        // In order to handle backwards compatibility between ruby 3 and 2
        // ruby2_keywords was introduced. It is called only on methods
        // with splat and changes they way they handle them.
        // We are just going to not compile these.
        // https://www.rubydoc.info/stdlib/core/Proc:ruby2_keywords
        if unsafe { get_iseq_flags_ruby2_keywords(self.jit.iseq) && call_info.flags.is_splat() } {
            gen_counter_incr!(&mut self.asm, send_iseq_ruby2_keywords);
            return CodegenStatus::CantCompile;
        }

        let iseq_has_rest = unsafe { get_iseq_flags_has_rest(iseq) };
        if iseq_has_rest && captured_opnd.is_some() {
            gen_counter_incr!(&mut self.asm, send_iseq_has_rest_and_captured);
            return CodegenStatus::CantCompile;
        }

        if iseq_has_rest && call_info.flags.is_splat() {
            gen_counter_incr!(&mut self.asm, send_iseq_has_rest_and_splat);
            return CodegenStatus::CantCompile;
        }

        if iseq_has_rest && call_info.flags.is_opt_send() {
            gen_counter_incr!(&mut self.asm, send_iseq_has_rest_and_send);
            return CodegenStatus::CantCompile;
        }

        if iseq_has_rest && unsafe { get_iseq_flags_has_block(iseq) } {
            gen_counter_incr!(&mut self.asm, send_iseq_has_rest_and_block);
            return CodegenStatus::CantCompile;
        }

        if iseq_has_rest && unsafe { get_iseq_flags_has_kw(iseq) } {
            gen_counter_incr!(&mut self.asm, send_iseq_has_rest_and_kw);
            return CodegenStatus::CantCompile;
        }

        // If we have keyword arguments being passed to a callee that only takes
        // positionals, then we need to allocate a hash. For now we're going to
        // call that too complex and bail.
        if supplying_kws && !unsafe { get_iseq_flags_has_kw(iseq) } {
            gen_counter_incr!(&mut self.asm, send_iseq_has_no_kw);
            return CodegenStatus::CantCompile;
        }

        // If we have a method accepting no kwargs (**nil), exit if we have passed
        // it any kwargs.
        if supplying_kws && unsafe { get_iseq_flags_accepts_no_kwarg(iseq) } {
            gen_counter_incr!(&mut self.asm, send_iseq_accepts_no_kwarg);
            return CodegenStatus::CantCompile;
        }

        // For computing number of locals to set up for the callee
        let mut num_params = unsafe { get_iseq_body_param_size(iseq) };

        // Block parameter handling. This mirrors setup_parameters_complex().
        if unsafe { get_iseq_flags_has_block(iseq) } {
            if unsafe { get_iseq_body_local_iseq(iseq) == iseq } {
                num_params -= 1;
            } else {
                // In this case (param.flags.has_block && local_iseq != iseq),
                // the block argument is setup as a local variable and requires
                // materialization (allocation). Bail.
                gen_counter_incr!(&mut self.asm, send_iseq_materialized_block);
                return CodegenStatus::CantCompile;
            }
        }

        if call_info.flags.is_splat() && call_info.flags.is_zsuper() {
            // zsuper methods are super calls without any arguments.
            // They are also marked as splat, but don't actually have an array
            // they pull arguments from, instead we need to change to call
            // a different method with the current stack.
            gen_counter_incr!(&mut self.asm, send_iseq_zsuper);
            return CodegenStatus::CantCompile;
        }

        let mut start_pc_offset = 0;
        let required_num = unsafe { get_iseq_body_param_lead_num(iseq) };

        // This struct represents the metadata about the caller-specified
        // keyword arguments.
        let kw_arg_num = call_info.kw_arg_count();

        // Arity handling and optional parameter setup
        let opts_filled = argc - required_num - kw_arg_num;
        let opt_num = unsafe { get_iseq_body_param_opt_num(iseq) };
        let opts_missing: i32 = opt_num - opts_filled;

        if doing_kw_call && call_info.flags.is_splat() {
            gen_counter_incr!(&mut self.asm, send_iseq_splat_with_kw);
            return CodegenStatus::CantCompile;
        }

        if iseq_has_rest && opt_num != 0 {
            gen_counter_incr!(&mut self.asm, send_iseq_has_rest_and_optional);
            return CodegenStatus::CantCompile;
        }

        if opts_filled < 0 && !call_info.flags.is_splat() {
            // Too few arguments and no splat to make up for it
            gen_counter_incr!(&mut self.asm, send_iseq_arity_error);
            return CodegenStatus::CantCompile;
        }

        if opts_filled > opt_num && !iseq_has_rest {
            // Too many arguments and no place to put them (i.e. rest arg)
            gen_counter_incr!(&mut self.asm, send_iseq_arity_error);
            return CodegenStatus::CantCompile;
        }

        let block_arg = call_info.flags.is_block_arg();
        let block_arg_type = if block_arg {
            Some(self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)))
        } else {
            None
        };

        match block_arg_type {
            Some(Type::Nil | Type::BlockParamProxy) => {
                // We'll handle this later
            }
            None => {
                // Nothing to do
            }
            _ => {
                gen_counter_incr!(&mut self.asm, send_block_arg);
                return CodegenStatus::CantCompile;
            }
        }

        // If we have unfilled optional arguments and keyword arguments then we
        // would need to adjust the arguments location to account for that.
        // For now we aren't handling this case.
        if doing_kw_call && opts_missing > 0 {
            gen_counter_incr!(&mut self.asm, send_iseq_missing_optional_kw);
            return CodegenStatus::CantCompile;
        }

        // We will handle splat case later
        if opt_num > 0 && !call_info.flags.is_splat() {
            num_params -= opts_missing as u32;
            unsafe {
                let opt_table = get_iseq_body_param_opt_table(iseq);
                start_pc_offset = (*opt_table.offset(opts_filled as isize)).as_u32();
            }
        }

        if doing_kw_call {
            // Here we're calling a method with keyword arguments and specifying
            // keyword arguments at this call site.

            // This struct represents the metadata about the callee-specified
            // keyword parameters.
            let keyword = unsafe { get_iseq_body_param_keyword(iseq) };
            let keyword_num: usize = unsafe { (*keyword).num }.try_into().unwrap();
            let keyword_required_num: usize =
                unsafe { (*keyword).required_num }.try_into().unwrap();

            let mut required_kwargs_filled = 0;

            if keyword_num > 30 {
                // We have so many keywords that (1 << num) encoded as a FIXNUM
                // (which shifts it left one more) no longer fits inside a 32-bit
                // immediate.
                gen_counter_incr!(&mut self.asm, send_iseq_too_many_kwargs);
                return CodegenStatus::CantCompile;
            }

            // Check that the kwargs being passed are valid
            if supplying_kws {
                // This is the list of keyword arguments that the callee specified
                // in its initial declaration.
                // SAFETY: see compile.c for sizing of this slice.
                let callee_kwargs = unsafe { slice::from_raw_parts((*keyword).table, keyword_num) };

                // Here we're going to build up a list of the IDs that correspond to
                // the caller-specified keyword arguments. If they're not in the
                // same order as the order specified in the callee declaration, then
                // we're going to need to generate some code to swap values around
                // on the stack.
                let kw_arg_keyword_len: usize = kw_arg_num.try_into().unwrap();
                let mut caller_kwargs: Vec<ID> = vec![0; kw_arg_keyword_len];
                for (kwarg_idx, kwarg) in caller_kwargs
                    .iter_mut()
                    .enumerate()
                    .take(kw_arg_keyword_len)
                {
                    let sym = call_info.get_keyword_arg_symbol(kwarg_idx);
                    *kwarg = unsafe { rb_sym2id(sym) };
                }

                // First, we're going to be sure that the names of every
                // caller-specified keyword argument correspond to a name in the
                // list of callee-specified keyword parameters.
                for caller_kwarg in caller_kwargs {
                    let search_result = callee_kwargs
                        .iter()
                        .enumerate() // inject element index
                        .find(|(_, &kwarg)| kwarg == caller_kwarg);

                    match search_result {
                        None => {
                            // If the keyword was never found, then we know we have a
                            // mismatch in the names of the keyword arguments, so we need to
                            // bail.
                            gen_counter_incr!(&mut self.asm, send_iseq_kwargs_mismatch);
                            return CodegenStatus::CantCompile;
                        }
                        Some((callee_idx, _)) if callee_idx < keyword_required_num => {
                            // Keep a count to ensure all required kwargs are specified
                            required_kwargs_filled += 1;
                        }
                        _ => (),
                    }
                }
            }
            assert!(required_kwargs_filled <= keyword_required_num);
            if required_kwargs_filled != keyword_required_num {
                gen_counter_incr!(&mut self.asm, send_iseq_kwargs_mismatch);
                return CodegenStatus::CantCompile;
            }
        }

        // Number of locals that are not parameters
        let num_locals =
            unsafe { get_iseq_body_local_table_size(iseq) as i32 } - (num_params as i32);

        match block_arg_type {
            Some(Type::Nil) => {
                // We have a nil block arg, so let's pop it off the args
                self.ctx.stack_pop(1);
            }
            Some(Type::BlockParamProxy) => {
                // We don't need the actual stack value
                self.ctx.stack_pop(1);
            }
            None => {
                // Nothing to do
            }
            _ => {
                unreachable!("block_arg_type should be None, Nil, or BlockParamProxy");
            }
        }

        let leaf_builtin_raw = unsafe { rb_leaf_builtin_function(iseq) };
        let leaf_builtin: Option<*const rb_builtin_function> = if leaf_builtin_raw.is_null() {
            None
        } else {
            Some(leaf_builtin_raw)
        };
        if let (None, Some(builtin_info)) = (block, leaf_builtin) {
            // this is a .send call not currently supported for builtins
            if call_info.flags.is_opt_send() {
                gen_counter_incr!(&mut self.asm, send_send_builtin);
                return CodegenStatus::CantCompile;
            }

            let builtin_argc = unsafe { (*builtin_info).argc };
            if builtin_argc + 1 < (C_ARG_OPNDS.len() as i32) {
                self.asm.comment("inlined leaf builtin");

                // Save the PC and SP because the callee may allocate
                // e.g. Integer#abs on a bignum
                self.jit_prepare_routine_call();

                // Call the builtin func (ec, recv, arg1, arg2, ...)
                let mut args = vec![EC];

                // Copy self and arguments
                for i in 0..=builtin_argc {
                    let stack_opnd = self.ctx.stack_opnd(builtin_argc - i);
                    args.push(stack_opnd);
                }
                self.ctx.stack_pop((builtin_argc + 1).try_into().unwrap());
                let val = self
                    .asm
                    .ccall(unsafe { (*builtin_info).func_ptr as *const u8 }, args);

                // Push the return value
                let stack_ret = self.ctx.stack_push(Type::Unknown);
                self.asm.mov(stack_ret, val);

                // Note: assuming that the leaf builtin doesn't change local variables here.
                // Seems like a safe assumption.

                return CodegenStatus::KeepCompiling;
            }
        }

        // Stack overflow check
        // Note that vm_push_frame checks it against a decremented cfp, hence the multiply by 2.
        // #define CHECK_VM_STACK_OVERFLOW0(cfp, sp, margin)
        self.asm.comment("stack overflow check");
        let stack_max: i32 = unsafe { get_iseq_body_stack_max(iseq) }.try_into().unwrap();
        let locals_offs =
            SIZEOF_VALUE_I32 * (num_locals + stack_max) + 2 * (RUBY_SIZEOF_CONTROL_FRAME as i32);
        let stack_limit = self.asm.lea(self.ctx.sp_opnd(locals_offs as isize));
        self.asm.cmp(CFP, stack_limit);
        let exit = counted_exit!(self.get_ocb(), side_exit, send_se_cf_overflow);
        self.asm.jbe(exit);

        // Check if we need the arg0 splat handling of vm_callee_setup_block_arg
        let arg_setup_block = captured_opnd.is_some(); // arg_setup_type: arg_setup_block (invokeblock)
        let block_arg0_splat = arg_setup_block
            && argc == 1
            && unsafe { get_iseq_flags_has_lead(iseq) && !get_iseq_flags_ambiguous_param0(iseq) };

        // push_splat_args does stack manipulation so we can no longer side exit
        if call_info.flags.is_splat() {
            // If block_arg0_splat, we still need side exits after this, but
            // doing push_splat_args here disallows it. So bail out.
            if block_arg0_splat {
                gen_counter_incr!(&mut self.asm, invokeblock_iseq_arg0_args_splat);
                return CodegenStatus::CantCompile;
            }

            let array = self
                .jit
                .peek_at_stack(&self.ctx, if block_arg { 1 } else { 0 });
            let array_length = if array == Qnil {
                0
            } else {
                unsafe { rb_yjit_array_len(array) as u32 }
            };

            if opt_num == 0 && required_num != array_length as i32 {
                gen_counter_incr!(&mut self.asm, send_iseq_splat_arity_error);
                return CodegenStatus::CantCompile;
            }

            let remaining_opt = (opt_num as u32 + required_num as u32)
                .saturating_sub(array_length + (argc as u32 - 1));

            if opt_num > 0 {
                // We are going to jump to the correct offset based on how many optional
                // params are remaining.
                unsafe {
                    let opt_table = get_iseq_body_param_opt_table(iseq);
                    let offset = (opt_num - remaining_opt as i32) as isize;
                    start_pc_offset = (*opt_table.offset(offset)).as_u32();
                };
            }
            // We are going to assume that the splat fills
            // all the remaining arguments. In the generated code
            // we test if this is true and if not side exit.
            argc = argc - 1 + array_length as i32 + remaining_opt as i32;
            self.push_splat_args(array_length, side_exit);

            for _ in 0..remaining_opt {
                // We need to push nil for the optional arguments
                let stack_ret = self.ctx.stack_push(Type::Unknown);
                self.asm.mov(stack_ret, Qnil.into());
            }
        }

        // This is a .send call and we need to adjust the stack
        if call_info.flags.is_opt_send() {
            self.handle_opt_send_shift_stack(argc);
        }

        if doing_kw_call {
            // Here we're calling a method with keyword arguments and specifying
            // keyword arguments at this call site.

            // The block_arg0_splat implementation is for the rb_simple_iseq_p case,
            // but doing_kw_call means it's not a simple ISEQ.
            if block_arg0_splat {
                gen_counter_incr!(&mut self.asm, invokeblock_iseq_arg0_has_kw);
                return CodegenStatus::CantCompile;
            }

            // Number of positional arguments the callee expects before the first
            // keyword argument
            let args_before_kw = required_num + opt_num;

            // This struct represents the metadata about the caller-specified
            // keyword arguments.
            let caller_keyword_len: usize = call_info.kw_arg_count() as usize;

            // This struct represents the metadata about the callee-specified
            // keyword parameters.
            let keyword = unsafe { get_iseq_body_param_keyword(iseq) };

            self.asm.comment("keyword args");

            // This is the list of keyword arguments that the callee specified
            // in its initial declaration.
            let callee_kwargs = unsafe { (*keyword).table };
            let total_kwargs: usize = unsafe { (*keyword).num }.try_into().unwrap();

            // Here we're going to build up a list of the IDs that correspond to
            // the caller-specified keyword arguments. If they're not in the
            // same order as the order specified in the callee declaration, then
            // we're going to need to generate some code to swap values around
            // on the stack.
            let mut caller_kwargs: Vec<ID> = vec![0; total_kwargs];

            for (kwarg_idx, kwargs) in caller_kwargs
                .iter_mut()
                .enumerate()
                .take(caller_keyword_len)
            {
                let sym = call_info.get_keyword_arg_symbol(kwarg_idx);
                *kwargs = unsafe { rb_sym2id(sym) };
            }
            let mut kwarg_idx = caller_keyword_len;

            let mut unspecified_bits = 0;

            let keyword_required_num: usize =
                unsafe { (*keyword).required_num }.try_into().unwrap();
            for callee_idx in keyword_required_num..total_kwargs {
                let mut already_passed = false;
                let callee_kwarg =
                    unsafe { *(callee_kwargs.offset(callee_idx.try_into().unwrap())) };

                for caller in caller_kwargs.iter().take(caller_keyword_len) {
                    if *caller == callee_kwarg {
                        already_passed = true;
                        break;
                    }
                }

                if !already_passed {
                    // Reserve space on the stack for each default value we'll be
                    // filling in (which is done in the next loop). Also increments
                    // argc so that the callee's SP is recorded correctly.
                    argc += 1;
                    let default_arg = self.ctx.stack_push(Type::Unknown);

                    // callee_idx - keyword->required_num is used in a couple of places below.
                    let req_num: isize = unsafe { (*keyword).required_num }.try_into().unwrap();
                    let callee_idx_isize: isize = callee_idx.try_into().unwrap();
                    let extra_args = callee_idx_isize - req_num;

                    //VALUE default_value = keyword->default_values[callee_idx - keyword->required_num];
                    let mut default_value =
                        unsafe { *((*keyword).default_values.offset(extra_args)) };

                    if default_value == Qundef {
                        // Qundef means that this value is not constant and must be
                        // recalculated at runtime, so we record it in unspecified_bits
                        // (Qnil is then used as a placeholder instead of Qundef).
                        unspecified_bits |= 0x01 << extra_args;
                        default_value = Qnil;
                    }

                    self.asm.mov(default_arg, default_value.into());

                    caller_kwargs[kwarg_idx] = callee_kwarg;
                    kwarg_idx += 1;
                }
            }

            assert!(kwarg_idx == total_kwargs);

            // Next, we're going to loop through every keyword that was
            // specified by the caller and make sure that it's in the correct
            // place. If it's not we're going to swap it around with another one.
            for kwarg_idx in 0..total_kwargs {
                let kwarg_idx_isize: isize = kwarg_idx.try_into().unwrap();
                let callee_kwarg = unsafe { *(callee_kwargs.offset(kwarg_idx_isize)) };

                // If the argument is already in the right order, then we don't
                // need to generate any code since the expected value is already
                // in the right place on the stack.
                if callee_kwarg == caller_kwargs[kwarg_idx] {
                    continue;
                }

                // In this case the argument is not in the right place, so we
                // need to find its position where it _should_ be and swap with
                // that location.
                for swap_idx in (kwarg_idx + 1)..total_kwargs {
                    if callee_kwarg == caller_kwargs[swap_idx] {
                        // First we're going to generate the code that is going
                        // to perform the actual swapping at runtime.
                        let swap_idx_i32: i32 = swap_idx.try_into().unwrap();
                        let kwarg_idx_i32: i32 = kwarg_idx.try_into().unwrap();
                        let offset0: u16 = (argc - 1 - swap_idx_i32 - args_before_kw)
                            .try_into()
                            .unwrap();
                        let offset1: u16 = (argc - 1 - kwarg_idx_i32 - args_before_kw)
                            .try_into()
                            .unwrap();
                        self.stack_swap(offset0, offset1);

                        // Next we're going to do some bookkeeping on our end so
                        // that we know the order that the arguments are
                        // actually in now.
                        caller_kwargs.swap(kwarg_idx, swap_idx);

                        break;
                    }
                }
            }

            // Keyword arguments cause a special extra local variable to be
            // pushed onto the stack that represents the parameters that weren't
            // explicitly given a value and have a non-constant default.
            let unspec_opnd = VALUE::fixnum_from_usize(unspecified_bits).as_u64();
            self.asm.mov(self.ctx.stack_opnd(-1), unspec_opnd.into());
        }

        // Same as vm_callee_setup_block_arg_arg0_check and vm_callee_setup_block_arg_arg0_splat
        // on vm_callee_setup_block_arg for arg_setup_block. This is done after CALLER_SETUP_ARG
        // and CALLER_REMOVE_EMPTY_KW_SPLAT, so this implementation is put here. This may need
        // side exits, so you still need to allow side exits here if block_arg0_splat is true.
        // Note that you can't have side exits after this arg0 splat.
        if block_arg0_splat {
            let arg0_opnd = self.ctx.stack_opnd(0);

            // Only handle the case that you don't need to_ary conversion
            let not_array_exit =
                counted_exit!(self.get_ocb(), side_exit, invokeblock_iseq_arg0_not_array);
            self.guard_object_is_array(arg0_opnd, arg0_opnd.into(), not_array_exit);

            // Only handle the same that the array length == ISEQ's lead_num (most common)
            let arg0_len_opnd = self.get_array_len(arg0_opnd);
            let lead_num = unsafe { rb_get_iseq_body_param_lead_num(iseq) };
            self.asm.cmp(arg0_len_opnd, lead_num.into());
            let exit = counted_exit!(self.get_ocb(), side_exit, invokeblock_iseq_arg0_wrong_len);
            self.asm.jne(exit);

            let arg0_reg = self.asm.load(arg0_opnd);
            let array_opnd = self.get_array_ptr(arg0_reg);
            self.asm.comment("push splat arg0 onto the stack");
            self.ctx.stack_pop(argc.try_into().unwrap());
            for i in 0..lead_num {
                let stack_opnd = self.ctx.stack_push(Type::Unknown);
                self.asm
                    .mov(stack_opnd, Opnd::mem(64, array_opnd, SIZEOF_VALUE_I32 * i));
            }
            argc = lead_num;
        }

        if iseq_has_rest {
            assert!(argc >= required_num);

            // We are going to allocate so setting pc and sp.
            jit_save_pc(&self.jit, &mut self.asm);
            gen_save_sp(&mut self.asm, &mut self.ctx);

            let n = (argc - required_num) as u32;
            argc = required_num + 1;
            // If n is 0, then elts is never going to be read, so we can just pass null
            let values_ptr = if n == 0 {
                Opnd::UImm(0)
            } else {
                self.asm.comment("load pointer to array elts");
                let offset_magnitude = SIZEOF_VALUE as u32 * n;
                let values_opnd = self.ctx.sp_opnd(-(offset_magnitude as isize));
                self.asm.lea(values_opnd)
            };

            let new_ary = self.asm.ccall(
                rb_ec_ary_new_from_values as *const u8,
                vec![EC, Opnd::UImm(n.into()), values_ptr],
            );

            self.ctx.stack_pop(n.into_usize());
            let stack_ret = self.ctx.stack_push(Type::CArray);
            self.asm.mov(stack_ret, new_ary);
        }

        // Points to the receiver operand on the stack unless a captured environment is used
        let recv = match captured_opnd {
            Some(captured_opnd) => self.asm.load(Opnd::mem(64, captured_opnd, 0)), // captured->self
            _ => self.ctx.stack_opnd(argc),
        };
        let captured_self = captured_opnd.is_some();
        let sp_offset = (argc as isize) + if captured_self { 0 } else { 1 };

        // Store the updated SP on the current frame (pop arguments and receiver)
        self.asm.comment("store caller sp");
        let caller_sp = self
            .asm
            .lea(self.ctx.sp_opnd((SIZEOF_VALUE as isize) * -sp_offset));
        self.asm
            .store(Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SP), caller_sp);

        // Store the next PC in the current frame
        jit_save_pc(&self.jit, &mut self.asm);

        // Adjust the callee's stack pointer
        let offs = (SIZEOF_VALUE as isize)
            * (3 + (num_locals as isize) + if doing_kw_call { 1 } else { 0 });
        let callee_sp = self.asm.lea(self.ctx.sp_opnd(offs));

        let specval = if let Some(prev_ep) = prev_ep {
            // We've already side-exited if the callee expects a block, so we
            // ignore any supplied block here
            SpecVal::PrevEP(prev_ep)
        } else if let Some(captured_opnd) = captured_opnd {
            let ep_opnd = self
                .asm
                .load(Opnd::mem(64, captured_opnd, SIZEOF_VALUE_I32)); // captured->ep
            SpecVal::PrevEPOpnd(ep_opnd)
        } else if block_arg_type == Some(Type::BlockParamProxy) {
            SpecVal::BlockParamProxy
        } else if let Some(block_val) = block {
            SpecVal::BlockISeq(block_val)
        } else {
            SpecVal::None
        };

        // Setup the new frame
        self.gen_push_frame(
            true,
            ControlFrame {
                frame_type,
                specval,
                cme,
                recv,
                sp: callee_sp,
                iseq: Some(iseq),
                pc: None, // We are calling into jitted code, which will set the PC as necessary
                local_size: num_locals,
            },
        );

        // No need to set cfp->pc since the callee sets it whenever calling into routines
        // that could look at it through jit_save_pc().
        // mov(cb, REG0, const_ptr_opnd(start_pc));
        // mov(cb, member_opnd(REG_CFP, rb_control_frame_t, pc), REG0);

        // Stub so we can return to JITted code
        let return_block = BlockId {
            iseq: self.jit.iseq,
            idx: self.jit.next_insn_idx(),
        };

        // Create a context for the callee
        let mut callee_ctx = Context::default();

        // Set the argument types in the callee's context
        for arg_idx in 0..argc {
            let stack_offs: u8 = (argc - arg_idx - 1).try_into().unwrap();
            let arg_type = self.ctx.get_opnd_type(YARVOpnd::StackOpnd(stack_offs));
            callee_ctx.set_local_type(arg_idx.try_into().unwrap(), arg_type);
        }

        let recv_type = if captured_self {
            Type::Unknown // we don't track the type information of captured->self for now
        } else {
            self.ctx
                .get_opnd_type(YARVOpnd::StackOpnd(argc.try_into().unwrap()))
        };
        callee_ctx.upgrade_opnd_type(YARVOpnd::SelfOpnd, recv_type);

        // The callee might change locals through Kernel#binding and other means.
        self.ctx.clear_local_types();

        // Pop arguments and receiver in return context, push the return value
        // After the return, sp_offset will be 1. The codegen for leave writes
        // the return value in case of JIT-to-JIT return.
        let mut return_ctx = self.ctx.clone();
        return_ctx.stack_pop(sp_offset.try_into().unwrap());
        return_ctx.stack_push(Type::Unknown);
        return_ctx.set_sp_offset(1);
        return_ctx.reset_chain_depth();

        // Write the JIT return address on the callee frame
        gen_branch(
            self,
            return_block,
            &return_ctx,
            None,
            None,
            BranchGenFn::JITReturn,
        );

        // Directly jump to the entry point of the callee
        gen_direct_jump(
            &mut self.jit,
            &callee_ctx,
            BlockId {
                iseq,
                idx: start_pc_offset,
            },
            &mut self.asm,
        );

        CodegenStatus::EndBlock
    }

    fn gen_struct_aref(
        &mut self,
        ci: *const rb_callinfo,
        cme: *const rb_callable_method_entry_t,
        comptime_recv: VALUE,
        call_info: CallInfo,
        argc: i32,
    ) -> CodegenStatus {
        if unsafe { vm_ci_argc(ci) } != 0 {
            return CodegenStatus::CantCompile;
        }

        let off: i32 = unsafe { get_cme_def_body_optimized_index(cme) }
            .try_into()
            .unwrap();

        // Confidence checks
        assert!(unsafe { RB_TYPE_P(comptime_recv, RUBY_T_STRUCT) });
        assert!((off as i64) < unsafe { RSTRUCT_LEN(comptime_recv) });

        // We are going to use an encoding that takes a 4-byte immediate which
        // limits the offset to INT32_MAX.
        {
            let native_off = (off as i64) * (SIZEOF_VALUE as i64);
            if native_off > (i32::MAX as i64) {
                return CodegenStatus::CantCompile;
            }
        }

        // This is a .send call and we need to adjust the stack
        if call_info.flags.is_opt_send() {
            self.handle_opt_send_shift_stack(argc);
        }

        // All structs from the same Struct class should have the same
        // length. So if our comptime_recv is embedded all runtime
        // structs of the same class should be as well, and the same is
        // true of the converse.
        let embedded = unsafe { FL_TEST_RAW(comptime_recv, VALUE(RSTRUCT_EMBED_LEN_MASK)) };

        self.asm.comment("struct aref");

        let recv = self.asm.load(self.ctx.stack_pop(1));

        let val = if embedded != VALUE(0) {
            Opnd::mem(
                64,
                recv,
                RUBY_OFFSET_RSTRUCT_AS_ARY + (SIZEOF_VALUE_I32 * off),
            )
        } else {
            let rstruct_ptr = self
                .asm
                .load(Opnd::mem(64, recv, RUBY_OFFSET_RSTRUCT_AS_HEAP_PTR));
            Opnd::mem(64, rstruct_ptr, SIZEOF_VALUE_I32 * off)
        };

        let ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(ret, val);

        self.jump_to_next_insn();
        CodegenStatus::EndBlock
    }

    fn gen_struct_aset(
        &mut self,
        ci: *const rb_callinfo,
        cme: *const rb_callable_method_entry_t,
        comptime_recv: VALUE,
        call_info: CallInfo,
        argc: i32,
    ) -> CodegenStatus {
        if unsafe { vm_ci_argc(ci) } != 1 {
            return CodegenStatus::CantCompile;
        }

        // This is a .send call and we need to adjust the stack
        if call_info.flags.is_opt_send() {
            self.handle_opt_send_shift_stack(argc);
        }

        let off: i32 = unsafe { get_cme_def_body_optimized_index(cme) }
            .try_into()
            .unwrap();

        // Confidence checks
        assert!(unsafe { RB_TYPE_P(comptime_recv, RUBY_T_STRUCT) });
        assert!((off as i64) < unsafe { RSTRUCT_LEN(comptime_recv) });

        self.asm.comment("struct aset");

        let val = self.ctx.stack_pop(1);
        let recv = self.ctx.stack_pop(1);

        let val = self.asm.ccall(
            RSTRUCT_SET as *const u8,
            vec![recv, (off as i64).into(), val],
        );

        let ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(ret, val);

        self.jump_to_next_insn();
        CodegenStatus::EndBlock
    }

    fn gen_send_general(
        &mut self,
        cd: *const rb_call_data,
        block: Option<IseqPtr>,
    ) -> CodegenStatus {
        // Relevant definitions:
        // rb_execution_context_t       : vm_core.h
        // invoker, cfunc logic         : method.h, vm_method.c
        // rb_callinfo                  : vm_callinfo.h
        // rb_callable_method_entry_t   : method.h
        // vm_call_cfunc_with_frame     : vm_insnhelper.c
        //
        // For a general overview for how the interpreter calls methods,
        // see vm_call_method().

        let ci = unsafe { get_call_data_ci(cd) }; // info about the call site
        let mut argc: i32 = unsafe { vm_ci_argc(ci) }.try_into().unwrap();
        let mut mid = unsafe { vm_ci_mid(ci) };
        let mut call_info = CallInfo::new(ci);

        // Don't JIT calls with keyword splat
        if call_info.flags.is_kw_splat() {
            gen_counter_incr!(&mut self.asm, send_kw_splat);
            return CodegenStatus::CantCompile;
        }

        // Defer compilation so we can specialize on class of receiver
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        let recv_idx = argc + if call_info.flags.is_block_arg() { 1 } else { 0 };
        let comptime_recv = self.jit.peek_at_stack(&self.ctx, recv_idx as isize);
        let comptime_recv_klass = comptime_recv.class_of();

        // Guard that the receiver has the same class as the one from compile time
        let side_exit = self.get_side_exit(&self.ctx.clone());

        // Points to the receiver operand on the stack
        let recv = self.ctx.stack_opnd(recv_idx);
        let recv_opnd: YARVOpnd = recv.into();

        // Log the name of the method we're calling to
        #[cfg(feature = "disasm")]
        {
            use crate::cruby::{cstr_to_rust_string, rb_class2name, rb_id2name};
            let class_name = unsafe { cstr_to_rust_string(rb_class2name(comptime_recv_klass)) };
            let method_name = unsafe { cstr_to_rust_string(rb_id2name(mid)) };
            if let (Some(class_name), Some(method_name)) = (class_name, method_name) {
                self.asm
                    .comment(&format!("call to {}#{}", class_name, method_name))
            }
        }

        // Gather some statistics about sends
        gen_counter_incr!(&mut self.asm, num_send);
        if let Some(_known_klass) = self.ctx.get_opnd_type(recv_opnd).known_class() {
            gen_counter_incr!(&mut self.asm, num_send_known_class);
        }
        if self.ctx.get_chain_depth() > 1 {
            gen_counter_incr!(&mut self.asm, num_send_polymorphic);
        }

        let megamorphic_exit = counted_exit!(self.get_ocb(), side_exit, send_klass_megamorphic);
        self.jit_guard_known_klass(
            comptime_recv_klass,
            recv,
            recv_opnd,
            comptime_recv,
            SEND_MAX_DEPTH,
            megamorphic_exit,
        );

        // Do method lookup
        let mut cme = unsafe { rb_callable_method_entry(comptime_recv_klass, mid) };
        if cme.is_null() {
            // TODO: counter
            return CodegenStatus::CantCompile;
        }

        let visi = unsafe { METHOD_ENTRY_VISI(cme) };
        match visi {
            METHOD_VISI_PUBLIC => {
                // Can always call public methods
            }
            METHOD_VISI_PRIVATE => {
                if !call_info.flags.is_fcall() {
                    // Can only call private methods with FCALL callsites.
                    // (at the moment they are callsites without a receiver or an explicit `self` receiver)
                    return CodegenStatus::CantCompile;
                }
            }
            METHOD_VISI_PROTECTED => {
                // If the method call is an FCALL, it is always valid
                if !call_info.flags.is_fcall() {
                    // otherwise we need an ancestry check to ensure the receiver is valid to be called
                    // as protected
                    self.jit_protected_callee_ancestry_guard(cme, side_exit);
                }
            }
            _ => {
                panic!("cmes should always have a visibility!");
            }
        }

        // Register block for invalidation
        //assert!(cme->called_id == mid);
        assume_method_lookup_stable(self, cme);

        // To handle the aliased method case (VM_METHOD_TYPE_ALIAS)
        loop {
            let def_type = unsafe { get_cme_def_type(cme) };

            match def_type {
                VM_METHOD_TYPE_ISEQ => {
                    let iseq = unsafe { get_def_iseq_ptr((*cme).def) };
                    let frame_type = VM_FRAME_MAGIC_METHOD | VM_ENV_FLAG_LOCAL;
                    return self
                        .gen_send_iseq(iseq, frame_type, None, cme, block, call_info, argc, None);
                }
                VM_METHOD_TYPE_CFUNC => {
                    return self.gen_send_cfunc(
                        ci,
                        cme,
                        block,
                        &comptime_recv_klass,
                        call_info,
                        argc,
                    );
                }
                VM_METHOD_TYPE_IVAR => {
                    if call_info.flags.is_splat() {
                        gen_counter_incr!(&mut self.asm, send_args_splat_ivar);
                        return CodegenStatus::CantCompile;
                    }

                    if argc != 0 {
                        // Argument count mismatch. Getters take no arguments.
                        gen_counter_incr!(&mut self.asm, send_getter_arity);
                        return CodegenStatus::CantCompile;
                    }

                    // This is a .send call not supported right now for getters
                    if call_info.flags.is_opt_send() {
                        gen_counter_incr!(&mut self.asm, send_send_getter);
                        return CodegenStatus::CantCompile;
                    }

                    if c_method_tracing_currently_enabled(&self.jit) {
                        // Can't generate code for firing c_call and c_return events
                        // :attr-tracing:
                        // Handling the C method tracing events for attr_accessor
                        // methods is easier than regular C methods as we know the
                        // "method" we are calling into never enables those tracing
                        // events. Once global invalidation runs, the code for the
                        // attr_accessor is invalidated and we exit at the closest
                        // instruction boundary which is always outside of the body of
                        // the attr_accessor code.
                        gen_counter_incr!(&mut self.asm, send_cfunc_tracing);
                        return CodegenStatus::CantCompile;
                    }

                    let ivar_name = unsafe { get_cme_def_body_attr_id(cme) };

                    if call_info.flags.is_block_arg() {
                        gen_counter_incr!(&mut self.asm, send_block_arg);
                        return CodegenStatus::CantCompile;
                    }

                    return self.gen_get_ivar(
                        SEND_MAX_DEPTH,
                        comptime_recv,
                        ivar_name,
                        recv,
                        recv_opnd,
                        side_exit,
                    );
                }
                VM_METHOD_TYPE_ATTRSET => {
                    if call_info.flags.is_splat() {
                        gen_counter_incr!(&mut self.asm, send_args_splat_attrset);
                        return CodegenStatus::CantCompile;
                    }
                    if call_info.flags.is_kw_arg() {
                        gen_counter_incr!(&mut self.asm, send_attrset_kwargs);
                        return CodegenStatus::CantCompile;
                    } else if argc != 1 || unsafe { !RB_TYPE_P(comptime_recv, RUBY_T_OBJECT) } {
                        gen_counter_incr!(&mut self.asm, send_ivar_set_method);
                        return CodegenStatus::CantCompile;
                    } else if c_method_tracing_currently_enabled(&self.jit) {
                        // Can't generate code for firing c_call and c_return events
                        // See :attr-tracing:
                        gen_counter_incr!(&mut self.asm, send_cfunc_tracing);
                        return CodegenStatus::CantCompile;
                    } else if call_info.flags.is_block_arg() {
                        gen_counter_incr!(&mut self.asm, send_block_arg);
                        return CodegenStatus::CantCompile;
                    } else {
                        let ivar_name = unsafe { get_cme_def_body_attr_id(cme) };
                        return self.gen_set_ivar(ivar_name, call_info, argc);
                    }
                }
                // Block method, e.g. define_method(:foo) { :my_block }
                VM_METHOD_TYPE_BMETHOD => {
                    if call_info.flags.is_splat() {
                        gen_counter_incr!(&mut self.asm, send_args_splat_bmethod);
                        return CodegenStatus::CantCompile;
                    }
                    return self.gen_send_bmethod(cme, block, call_info, argc);
                }
                VM_METHOD_TYPE_ALIAS => {
                    // Retrieve the aliased method and re-enter the switch
                    cme = unsafe { rb_aliased_callable_method_entry(cme) };
                    continue;
                }
                // Send family of methods, e.g. call/apply
                VM_METHOD_TYPE_OPTIMIZED => {
                    if call_info.flags.is_block_arg() {
                        gen_counter_incr!(&mut self.asm, send_block_arg);
                        return CodegenStatus::CantCompile;
                    }

                    let opt_type = unsafe { get_cme_def_body_optimized_type(cme) };
                    match opt_type {
                        OPTIMIZED_METHOD_TYPE_SEND => {
                            // This is for method calls like `foo.send(:bar)`
                            // The `send` method does not get its own stack frame.
                            // instead we look up the method and call it,
                            // doing some stack shifting based on the VM_CALL_OPT_SEND flag

                            let starting_context = self.ctx.clone();

                            // Reject nested cases such as `send(:send, :alias_for_send, :foo))`.
                            // We would need to do some stack manipulation here or keep track of how
                            // many levels deep we need to stack manipulate. Because of how exits
                            // currently work, we can't do stack manipulation until we will no longer
                            // side exit.
                            if call_info.flags.is_opt_send() {
                                gen_counter_incr!(&mut self.asm, send_send_nested);
                                return CodegenStatus::CantCompile;
                            }

                            if argc == 0 {
                                gen_counter_incr!(&mut self.asm, send_send_wrong_args);
                                return CodegenStatus::CantCompile;
                            }

                            argc -= 1;

                            let compile_time_name =
                                self.jit.peek_at_stack(&self.ctx, argc as isize);

                            if !compile_time_name.string_p() && !compile_time_name.static_sym_p() {
                                gen_counter_incr!(&mut self.asm, send_send_chain_not_string_or_sym);
                                return CodegenStatus::CantCompile;
                            }

                            mid = unsafe { rb_get_symbol_id(compile_time_name) };
                            if mid == 0 {
                                gen_counter_incr!(&mut self.asm, send_send_null_mid);
                                return CodegenStatus::CantCompile;
                            }

                            cme = unsafe { rb_callable_method_entry(comptime_recv_klass, mid) };
                            if cme.is_null() {
                                gen_counter_incr!(&mut self.asm, send_send_null_cme);
                                return CodegenStatus::CantCompile;
                            }

                            call_info.flags |= VM_CALL_FCALL | VM_CALL_OPT_SEND;

                            assume_method_lookup_stable(self, cme);

                            let (known_class, type_mismatch_exit) = {
                                if compile_time_name.string_p() {
                                    (
                                        unsafe { rb_cString },
                                        counted_exit!(
                                            self.get_ocb(),
                                            side_exit,
                                            send_send_chain_not_string
                                        ),
                                    )
                                } else {
                                    (
                                        unsafe { rb_cSymbol },
                                        counted_exit!(
                                            self.get_ocb(),
                                            side_exit,
                                            send_send_chain_not_sym
                                        ),
                                    )
                                }
                            };

                            let name_opnd = self.ctx.stack_opnd(argc);
                            self.jit_guard_known_klass(
                                known_class,
                                name_opnd,
                                name_opnd.into(),
                                compile_time_name,
                                2, // We have string or symbol, so max depth is 2
                                type_mismatch_exit,
                            );

                            // Need to do this here so we don't have too many live
                            // values for the register allocator.
                            let name_opnd = self.asm.load(name_opnd);

                            let symbol_id_opnd = self
                                .asm
                                .ccall(rb_get_symbol_id as *const u8, vec![name_opnd]);

                            self.asm.comment("chain_guard_send");
                            let chain_exit =
                                counted_exit!(self.get_ocb(), side_exit, send_send_chain);
                            self.asm.cmp(symbol_id_opnd, mid.into());
                            self.jit_chain_guard(
                                &starting_context,
                                JCC_JNE,
                                SEND_MAX_CHAIN_DEPTH,
                                chain_exit,
                            );

                            // We have changed the argc, call_info.flags, mid, and cme, so we need to re-enter the match
                            // and compile whatever method we found from send.
                            continue;
                        }
                        OPTIMIZED_METHOD_TYPE_CALL => {
                            if block.is_some() {
                                gen_counter_incr!(&mut self.asm, send_call_block);
                                return CodegenStatus::CantCompile;
                            }

                            if call_info.flags.is_kw_arg() {
                                gen_counter_incr!(&mut self.asm, send_call_kwarg);
                                return CodegenStatus::CantCompile;
                            }

                            if call_info.flags.is_splat() {
                                gen_counter_incr!(&mut self.asm, send_args_splat_opt_call);
                                return CodegenStatus::CantCompile;
                            }

                            // Optimize for single ractor mode and avoid runtime check for
                            // "defined with an un-shareable Proc in a different Ractor"
                            if !assume_single_ractor_mode(self) {
                                gen_counter_incr!(&mut self.asm, send_call_multi_ractor);
                                return CodegenStatus::CantCompile;
                            }

                            // If this is a .send call we need to adjust the stack
                            if call_info.flags.is_opt_send() {
                                self.handle_opt_send_shift_stack(argc);
                            }

                            // About to reset the SP, need to load this here
                            let recv_load = self.asm.load(recv);

                            let sp = self.asm.lea(self.ctx.sp_opnd(0));

                            // Save the PC and SP because the callee can make Ruby calls
                            self.jit_prepare_routine_call();

                            let kw_splat = call_info.flags & VM_CALL_KW_SPLAT;
                            let stack_argument_pointer =
                                self.asm.lea(Opnd::mem(64, sp, -(argc) * SIZEOF_VALUE_I32));

                            let ret = self.asm.ccall(
                                rb_optimized_call as *const u8,
                                vec![
                                    recv_load,
                                    EC,
                                    argc.into(),
                                    stack_argument_pointer,
                                    kw_splat.into(),
                                    VM_BLOCK_HANDLER_NONE.into(),
                                ],
                            );

                            self.ctx.stack_pop(argc as usize + 1);

                            let stack_ret = self.ctx.stack_push(Type::Unknown);
                            self.asm.mov(stack_ret, ret);
                            return CodegenStatus::KeepCompiling;
                        }
                        OPTIMIZED_METHOD_TYPE_BLOCK_CALL => {
                            gen_counter_incr!(&mut self.asm, send_optimized_method_block_call);
                            return CodegenStatus::CantCompile;
                        }
                        OPTIMIZED_METHOD_TYPE_STRUCT_AREF => {
                            if call_info.flags.is_splat() {
                                gen_counter_incr!(&mut self.asm, send_args_splat_aref);
                                return CodegenStatus::CantCompile;
                            }
                            return self.gen_struct_aref(ci, cme, comptime_recv, call_info, argc);
                        }
                        OPTIMIZED_METHOD_TYPE_STRUCT_ASET => {
                            if call_info.flags.is_splat() {
                                gen_counter_incr!(&mut self.asm, send_args_splat_aset);
                                return CodegenStatus::CantCompile;
                            }
                            return self.gen_struct_aset(ci, cme, comptime_recv, call_info, argc);
                        }
                        _ => {
                            panic!("unknown optimized method type!")
                        }
                    }
                }
                VM_METHOD_TYPE_ZSUPER => {
                    gen_counter_incr!(&mut self.asm, send_zsuper_method);
                    return CodegenStatus::CantCompile;
                }
                VM_METHOD_TYPE_UNDEF => {
                    gen_counter_incr!(&mut self.asm, send_undef_method);
                    return CodegenStatus::CantCompile;
                }
                VM_METHOD_TYPE_NOTIMPLEMENTED => {
                    gen_counter_incr!(&mut self.asm, send_not_implemented_method);
                    return CodegenStatus::CantCompile;
                }
                VM_METHOD_TYPE_MISSING => {
                    gen_counter_incr!(&mut self.asm, send_missing_method);
                    return CodegenStatus::CantCompile;
                }
                VM_METHOD_TYPE_REFINED => {
                    gen_counter_incr!(&mut self.asm, send_refined_method);
                    return CodegenStatus::CantCompile;
                }
                _ => {
                    unreachable!();
                }
            }
        }
    }

    /// Shifts the stack for send in order to remove the name of the method
    /// Comment below borrow from vm_call_opt_send in vm_insnhelper.c
    /// E.g. when argc == 2
    ///  |      |        |      |  TOPN
    ///  +------+        |      |
    ///  | arg1 | ---+   |      |    0
    ///  +------+    |   +------+
    ///  | arg0 | -+ +-> | arg1 |    1
    ///  +------+  |     +------+
    ///  | sym  |  +---> | arg0 |    2
    ///  +------+        +------+
    ///  | recv |        | recv |    3
    ///--+------+--------+------+------
    ///
    /// We do this for our compiletime context and the actual stack
    fn handle_opt_send_shift_stack(&mut self, argc: i32) {
        self.asm.comment("shift_stack");
        for j in (0..argc).rev() {
            let opnd = self.ctx.stack_opnd(j);
            let opnd2 = self.ctx.stack_opnd(j + 1);
            self.asm.mov(opnd2, opnd);
        }
        self.ctx.shift_stack(argc as usize);
    }

    fn gen_send(&mut self) -> CodegenStatus {
        let cd = self.jit.get_arg(0).as_ptr();
        let block = self.jit.get_arg(1).as_optional_ptr();
        self.gen_send_general(cd, block)
    }

    fn gen_invokeblock(&mut self) -> CodegenStatus {
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        // Get call info
        let cd = self.jit.get_arg(0).as_ptr();
        let ci = unsafe { get_call_data_ci(cd) };
        let argc: i32 = unsafe { vm_ci_argc(ci) }.try_into().unwrap();
        let call_info = CallInfo::new(ci);

        // Get block_handler
        let cfp = unsafe { get_ec_cfp(self.jit.ec.unwrap()) };
        let lep = unsafe { rb_vm_ep_local_ep(get_cfp_ep(cfp)) };
        let comptime_handler =
            unsafe { *lep.offset(VM_ENV_DATA_INDEX_SPECVAL.try_into().unwrap()) };

        // Handle each block_handler type
        if comptime_handler.0 == VM_BLOCK_HANDLER_NONE as usize {
            // no block given
            gen_counter_incr!(&mut self.asm, invokeblock_none);
            CodegenStatus::CantCompile
        } else if comptime_handler.0 & 0x3 == 0x1 {
            // VM_BH_ISEQ_BLOCK_P
            self.asm.comment("get local EP");
            let ep_opnd = self.gen_get_lep();
            let block_handler_opnd = self.asm.load(Opnd::mem(
                64,
                ep_opnd,
                SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_SPECVAL,
            ));

            self.asm.comment("guard block_handler type");
            let side_exit = self.get_side_exit(&self.ctx.clone());
            let tag_opnd = self.asm.and(block_handler_opnd, 0x3.into()); // block_handler is a tagged pointer
            self.asm.cmp(tag_opnd, 0x1.into()); // VM_BH_ISEQ_BLOCK_P
            let tag_changed_exit =
                counted_exit!(self.get_ocb(), side_exit, invokeblock_tag_changed);
            self.jit_chain_guard(
                &self.ctx.clone(),
                JCC_JNE,
                SEND_MAX_CHAIN_DEPTH,
                tag_changed_exit,
            );

            let comptime_captured = unsafe {
                ((comptime_handler.0 & !0x3) as *const rb_captured_block)
                    .as_ref()
                    .unwrap()
            };
            let comptime_iseq = unsafe { *comptime_captured.code.iseq.as_ref() };

            self.asm.comment("guard known ISEQ");
            let captured_opnd = self.asm.and(block_handler_opnd, Opnd::Imm(!0x3));
            let iseq_opnd = self
                .asm
                .load(Opnd::mem(64, captured_opnd, SIZEOF_VALUE_I32 * 2));
            self.asm.cmp(iseq_opnd, (comptime_iseq as usize).into());
            let block_changed_exit =
                counted_exit!(self.get_ocb(), side_exit, invokeblock_iseq_block_changed);
            self.jit_chain_guard(
                &self.ctx.clone(),
                JCC_JNE,
                SEND_MAX_CHAIN_DEPTH,
                block_changed_exit,
            );

            self.gen_send_iseq(
                comptime_iseq,
                VM_FRAME_MAGIC_BLOCK,
                None,
                0 as _,
                None,
                call_info,
                argc,
                Some(captured_opnd),
            )
        } else if comptime_handler.0 & 0x3 == 0x3 {
            // VM_BH_IFUNC_P
            // We aren't handling CALLER_SETUP_ARG and CALLER_REMOVE_EMPTY_KW_SPLAT yet.
            if call_info.flags.is_splat() {
                gen_counter_incr!(&mut self.asm, invokeblock_ifunc_args_splat);
                return CodegenStatus::CantCompile;
            }
            if call_info.flags.is_kw_splat() {
                gen_counter_incr!(&mut self.asm, invokeblock_ifunc_kw_splat);
                return CodegenStatus::CantCompile;
            }

            self.asm.comment("get local EP");
            let ep_opnd = self.gen_get_lep();
            let block_handler_opnd = self.asm.load(Opnd::mem(
                64,
                ep_opnd,
                SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_SPECVAL,
            ));

            self.asm.comment("guard block_handler type");
            let side_exit = self.get_side_exit(&self.ctx.clone());
            let tag_opnd = self.asm.and(block_handler_opnd, 0x3.into()); // block_handler is a tagged pointer
            self.asm.cmp(tag_opnd, 0x3.into()); // VM_BH_IFUNC_P
            let tag_changed_exit =
                counted_exit!(self.get_ocb(), side_exit, invokeblock_tag_changed);
            self.jit_chain_guard(
                &self.ctx.clone(),
                JCC_JNE,
                SEND_MAX_CHAIN_DEPTH,
                tag_changed_exit,
            );

            // The cfunc may not be leaf
            self.jit_prepare_routine_call();

            extern "C" {
                fn rb_vm_yield_with_cfunc(
                    ec: EcPtr,
                    captured: *const rb_captured_block,
                    argc: c_int,
                    argv: *const VALUE,
                ) -> VALUE;
            }
            self.asm.comment("call ifunc");
            let captured_opnd = self.asm.and(block_handler_opnd, Opnd::Imm(!0x3));
            let argv = self
                .asm
                .lea(self.ctx.sp_opnd((-argc * SIZEOF_VALUE_I32) as isize));
            let ret = self.asm.ccall(
                rb_vm_yield_with_cfunc as *const u8,
                vec![EC, captured_opnd, argc.into(), argv],
            );

            self.ctx.stack_pop(argc.try_into().unwrap());
            let stack_ret = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(stack_ret, ret);

            // cfunc calls may corrupt types
            self.ctx.clear_local_types();

            // Share the successor with other chains
            self.jump_to_next_insn();
            CodegenStatus::EndBlock
        } else if comptime_handler.symbol_p() {
            gen_counter_incr!(&mut self.asm, invokeblock_symbol);
            CodegenStatus::CantCompile
        } else {
            // Proc
            gen_counter_incr!(&mut self.asm, invokeblock_proc);
            CodegenStatus::CantCompile
        }
    }

    fn gen_invokesuper(&mut self) -> CodegenStatus {
        let cd: *const rb_call_data = self.jit.get_arg(0).as_ptr();
        let block: Option<IseqPtr> = self.jit.get_arg(1).as_optional_ptr();

        // Defer compilation so we can specialize on class of receiver
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        let me = unsafe { rb_vm_frame_method_entry(get_ec_cfp(self.jit.ec.unwrap())) };
        if me.is_null() {
            return CodegenStatus::CantCompile;
        }

        // FIXME: We should track and invalidate this block when this cme is invalidated
        let current_defined_class = unsafe { (*me).defined_class };
        let mid = unsafe { get_def_original_id((*me).def) };

        if me != unsafe { rb_callable_method_entry(current_defined_class, (*me).called_id) } {
            // Though we likely could generate this call, as we are only concerned
            // with the method entry remaining valid, assume_method_lookup_stable
            // below requires that the method lookup matches as well
            return CodegenStatus::CantCompile;
        }

        // vm_search_normal_superclass
        let rbasic_ptr: *const RBasic = current_defined_class.as_ptr();
        if current_defined_class.builtin_type() == RUBY_T_ICLASS
            && unsafe {
                RB_TYPE_P((*rbasic_ptr).klass, RUBY_T_MODULE)
                    && FL_TEST_RAW(
                        (*rbasic_ptr).klass,
                        VALUE(RMODULE_IS_REFINEMENT.into_usize()),
                    ) != VALUE(0)
            }
        {
            return CodegenStatus::CantCompile;
        }
        let comptime_superclass =
            unsafe { rb_class_get_superclass(RCLASS_ORIGIN(current_defined_class)) };

        let ci = unsafe { get_call_data_ci(cd) };
        let argc: i32 = unsafe { vm_ci_argc(ci) }.try_into().unwrap();
        let call_info = CallInfo::new(ci);

        // Don't JIT calls that aren't simple
        // Note, not using VM_CALL_ARGS_SIMPLE because sometimes we pass a block.

        if call_info.flags.is_kw_arg() {
            gen_counter_incr!(&mut self.asm, send_keywords);
            return CodegenStatus::CantCompile;
        }
        if call_info.flags.is_kw_splat() {
            gen_counter_incr!(&mut self.asm, send_kw_splat);
            return CodegenStatus::CantCompile;
        }
        if call_info.flags.is_block_arg() {
            gen_counter_incr!(&mut self.asm, send_block_arg);
            return CodegenStatus::CantCompile;
        }

        // Ensure we haven't rebound this method onto an incompatible class.
        // In the interpreter we try to avoid making this check by performing some
        // cheaper calculations first, but since we specialize on the method entry
        // and so only have to do this once at compile time this is fine to always
        // check and side exit.
        let comptime_recv = self.jit.peek_at_stack(&self.ctx, argc as isize);
        if unsafe { rb_obj_is_kind_of(comptime_recv, current_defined_class) } == VALUE(0) {
            return CodegenStatus::CantCompile;
        }

        // Do method lookup
        let cme = unsafe { rb_callable_method_entry(comptime_superclass, mid) };

        if cme.is_null() {
            return CodegenStatus::CantCompile;
        }

        // Check that we'll be able to write this method dispatch before generating checks
        let cme_def_type = unsafe { get_cme_def_type(cme) };
        if cme_def_type != VM_METHOD_TYPE_ISEQ && cme_def_type != VM_METHOD_TYPE_CFUNC {
            // others unimplemented
            return CodegenStatus::CantCompile;
        }

        // Guard that the receiver has the same class as the one from compile time
        let side_exit = self.get_side_exit(&self.ctx.clone());

        self.asm.comment("guard known me");
        let lep_opnd = self.gen_get_lep();
        let ep_me_opnd = Opnd::mem(64, lep_opnd, SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_ME_CREF);

        let me_as_value = VALUE(me as usize);
        self.asm.cmp(ep_me_opnd, me_as_value.into());
        let exit = counted_exit!(self.get_ocb(), side_exit, invokesuper_me_changed);
        self.asm.jne(exit);

        if block.is_none() {
            // Guard no block passed
            // rb_vm_frame_block_handler(GET_EC()->cfp) == VM_BLOCK_HANDLER_NONE
            // note, we assume VM_ASSERT(VM_ENV_LOCAL_P(ep))
            //
            // TODO: this could properly forward the current block handler, but
            // would require changes to gen_send_*
            self.asm.comment("guard no block given");
            let ep_specval_opnd =
                Opnd::mem(64, lep_opnd, SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_SPECVAL);
            self.asm.cmp(ep_specval_opnd, VM_BLOCK_HANDLER_NONE.into());
            let exit = counted_exit!(self.get_ocb(), side_exit, invokesuper_block);
            self.asm.jne(exit);
        }

        // We need to assume that both our current method entry and the super
        // method entry we invoke remain stable
        assume_method_lookup_stable(self, me);
        assume_method_lookup_stable(self, cme);

        // Method calls may corrupt types
        self.ctx.clear_local_types();

        match cme_def_type {
            VM_METHOD_TYPE_ISEQ => {
                let iseq = unsafe { get_def_iseq_ptr((*cme).def) };
                let frame_type = VM_FRAME_MAGIC_METHOD | VM_ENV_FLAG_LOCAL;
                self.gen_send_iseq(iseq, frame_type, None, cme, block, call_info, argc, None)
            }
            VM_METHOD_TYPE_CFUNC => {
                self.gen_send_cfunc(ci, cme, block, ptr::null(), call_info, argc)
            }
            _ => unreachable!(),
        }
    }

    fn gen_leave(&mut self) -> CodegenStatus {
        // Only the return value should be on the stack
        assert_eq!(1, self.ctx.get_stack_size());

        // Create a side-exit to fall back to the interpreter
        let side_exit = self.get_side_exit(&self.ctx.clone());
        let ocb_asm = Assembler::new();

        // Check for interrupts
        let exit = counted_exit!(self.get_ocb(), side_exit, leave_se_interrupt);
        gen_check_ints(&mut self.asm, exit);
        ocb_asm.compile(self.get_ocb().unwrap());

        // Pop the current frame (ec->cfp++)
        // Note: the return PC is already in the previous CFP
        self.asm.comment("pop stack frame");
        let incr_cfp = self.asm.add(CFP, RUBY_SIZEOF_CONTROL_FRAME.into());
        self.asm.mov(CFP, incr_cfp);
        self.asm.mov(Opnd::mem(64, EC, RUBY_OFFSET_EC_CFP), CFP);

        // Load the return value
        let retval_opnd = self.ctx.stack_pop(1);

        // Move the return value into the C return register for gen_leave_exit()
        self.asm.mov(C_RET_OPND, retval_opnd);

        // Reload REG_SP for the caller and write the return value.
        // Top of the stack is REG_SP[0] since the caller has sp_offset=1.
        self.asm.mov(SP, Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SP));
        self.asm.mov(Opnd::mem(64, SP, 0), C_RET_OPND);

        // Jump to the JIT return address on the frame that was just popped
        let offset_to_jit_return = -(RUBY_SIZEOF_CONTROL_FRAME as i32) + RUBY_OFFSET_CFP_JIT_RETURN;
        self.asm.jmp_opnd(Opnd::mem(64, CFP, offset_to_jit_return));

        CodegenStatus::EndBlock
    }

    fn gen_getglobal(&mut self) -> CodegenStatus {
        let gid = self.jit.get_arg(0).as_usize();

        // Save the PC and SP because we might make a Ruby call for warning
        self.jit_prepare_routine_call();

        let val_opnd = self.asm.ccall(rb_gvar_get as *const u8, vec![gid.into()]);

        let top = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(top, val_opnd);

        CodegenStatus::KeepCompiling
    }

    fn gen_setglobal(&mut self) -> CodegenStatus {
        let gid = self.jit.get_arg(0).as_usize();

        // Save the PC and SP because we might make a Ruby call for
        // Kernel#set_trace_var
        self.jit_prepare_routine_call();

        self.asm.ccall(
            rb_gvar_set as *const u8,
            vec![gid.into(), self.ctx.stack_pop(1)],
        );

        CodegenStatus::KeepCompiling
    }

    fn gen_anytostring(&mut self) -> CodegenStatus {
        // Save the PC and SP since we might call #to_s
        self.jit_prepare_routine_call();

        let str = self.ctx.stack_pop(1);
        let val = self.ctx.stack_pop(1);

        let val = self
            .asm
            .ccall(rb_obj_as_string_result as *const u8, vec![str, val]);

        // Push the return value
        let stack_ret = self.ctx.stack_push(Type::TString);
        self.asm.mov(stack_ret, val);

        CodegenStatus::KeepCompiling
    }

    fn gen_objtostring(&mut self) -> CodegenStatus {
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        let recv = self.ctx.stack_opnd(0);
        let comptime_recv = self.jit.peek_at_stack(&self.ctx, 0);

        if unsafe { RB_TYPE_P(comptime_recv, RUBY_T_STRING) } {
            let side_exit = self.get_side_exit(&self.ctx.clone());

            self.jit_guard_known_klass(
                comptime_recv.class_of(),
                recv,
                recv.into(),
                comptime_recv,
                SEND_MAX_DEPTH,
                side_exit,
            );
            // No work needed. The string value is already on the top of the stack.
            CodegenStatus::KeepCompiling
        } else {
            let cd = self.jit.get_arg(0).as_ptr();
            self.gen_send_general(cd, None)
        }
    }

    fn gen_intern(&mut self) -> CodegenStatus {
        // Save the PC and SP because we might allocate
        self.jit_prepare_routine_call();

        let str = self.ctx.stack_pop(1);
        let sym = self.asm.ccall(rb_str_intern as *const u8, vec![str]);

        // Push the return value
        let stack_ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(stack_ret, sym);

        CodegenStatus::KeepCompiling
    }

    fn gen_toregexp(&mut self) -> CodegenStatus {
        let opt = self.jit.get_arg(0).as_i64();
        let cnt = self.jit.get_arg(1).as_usize();

        // Save the PC and SP because this allocates an object and could
        // raise an exception.
        self.jit_prepare_routine_call();

        let values_ptr = self.asm.lea(
            self.ctx
                .sp_opnd(-((SIZEOF_VALUE as isize) * (cnt as isize))),
        );
        self.ctx.stack_pop(cnt);

        let ary = self.asm.ccall(
            rb_ary_tmp_new_from_values as *const u8,
            vec![Opnd::Imm(0), cnt.into(), values_ptr],
        );

        // Save the array so we can clear it later
        self.asm.cpush(ary);
        self.asm.cpush(ary); // Alignment

        let val = self
            .asm
            .ccall(rb_reg_new_ary as *const u8, vec![ary, Opnd::Imm(opt)]);

        // The actual regex is in RAX now.  Pop the temp array from
        // rb_ary_tmp_new_from_values into C arg regs so we can clear it
        let ary = self.asm.cpop(); // Alignment
        self.asm.cpop_into(ary);

        // The value we want to push on the stack is in RAX right now
        let stack_ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(stack_ret, val);

        // Clear the temp array.
        self.asm.ccall(rb_ary_clear as *const u8, vec![ary]);

        CodegenStatus::KeepCompiling
    }

    fn gen_getspecial(&mut self) -> CodegenStatus {
        // This takes two arguments, key and type
        // key is only used when type == 0
        // A non-zero type determines which type of backref to fetch
        //rb_num_t key = self.jit.jit_get_arg(0);
        let rtype = self.jit.get_arg(1).as_u64();

        if rtype == 0 {
            // not yet implemented
            CodegenStatus::CantCompile
        } else if rtype & 0x01 != 0 {
            // Fetch a "special" backref based on a char encoded by shifting by 1

            // Can raise if matchdata uninitialized
            self.jit_prepare_routine_call();

            // call rb_backref_get()
            self.asm.comment("rb_backref_get");
            let backref = self.asm.ccall(rb_backref_get as *const u8, vec![]);

            let rt_u8: u8 = (rtype >> 1).try_into().unwrap();
            let val = match rt_u8.into() {
                '&' => {
                    self.asm.comment("rb_reg_last_match");
                    self.asm
                        .ccall(rb_reg_last_match as *const u8, vec![backref])
                }
                '`' => {
                    self.asm.comment("rb_reg_match_pre");
                    self.asm.ccall(rb_reg_match_pre as *const u8, vec![backref])
                }
                '\'' => {
                    self.asm.comment("rb_reg_match_post");
                    self.asm
                        .ccall(rb_reg_match_post as *const u8, vec![backref])
                }
                '+' => {
                    self.asm.comment("rb_reg_match_last");
                    self.asm
                        .ccall(rb_reg_match_last as *const u8, vec![backref])
                }
                _ => panic!("invalid back-ref"),
            };

            let stack_ret = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(stack_ret, val);

            CodegenStatus::KeepCompiling
        } else {
            // Fetch the N-th match from the last backref based on type shifted by 1

            // Can raise if matchdata uninitialized
            self.jit_prepare_routine_call();

            // call rb_backref_get()
            self.asm.comment("rb_backref_get");
            let backref = self.asm.ccall(rb_backref_get as *const u8, vec![]);

            // rb_reg_nth_match((int)(type >> 1), backref);
            self.asm.comment("rb_reg_nth_match");
            let val = self.asm.ccall(
                rb_reg_nth_match as *const u8,
                vec![Opnd::Imm((rtype >> 1).try_into().unwrap()), backref],
            );

            let stack_ret = self.ctx.stack_push(Type::Unknown);
            self.asm.mov(stack_ret, val);

            CodegenStatus::KeepCompiling
        }
    }

    fn gen_getclassvariable(&mut self) -> CodegenStatus {
        // rb_vm_getclassvariable can raise exceptions.
        self.jit_prepare_routine_call();

        let val_opnd = self.asm.ccall(
            rb_vm_getclassvariable as *const u8,
            vec![
                Opnd::mem(64, CFP, RUBY_OFFSET_CFP_ISEQ),
                CFP,
                Opnd::UImm(self.jit.get_arg(0).as_u64()),
                Opnd::UImm(self.jit.get_arg(1).as_u64()),
            ],
        );

        let top = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(top, val_opnd);

        CodegenStatus::KeepCompiling
    }

    fn gen_setclassvariable(&mut self) -> CodegenStatus {
        // rb_vm_setclassvariable can raise exceptions.
        self.jit_prepare_routine_call();

        self.asm.ccall(
            rb_vm_setclassvariable as *const u8,
            vec![
                Opnd::mem(64, CFP, RUBY_OFFSET_CFP_ISEQ),
                CFP,
                Opnd::UImm(self.jit.get_arg(0).as_u64()),
                self.ctx.stack_pop(1),
                Opnd::UImm(self.jit.get_arg(1).as_u64()),
            ],
        );

        CodegenStatus::KeepCompiling
    }

    fn gen_getconstant(&mut self) -> CodegenStatus {
        let id = self.jit.get_arg(0).as_usize();

        // vm_get_ev_const can raise exceptions.
        self.jit_prepare_routine_call();

        let allow_nil_opnd = self.ctx.stack_pop(1);
        let klass_opnd = self.ctx.stack_pop(1);

        extern "C" {
            fn rb_vm_get_ev_const(ec: EcPtr, klass: VALUE, id: ID, allow_nil: VALUE) -> VALUE;
        }

        let val_opnd = self.asm.ccall(
            rb_vm_get_ev_const as *const u8,
            vec![EC, klass_opnd, id.into(), allow_nil_opnd],
        );

        let top = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(top, val_opnd);

        CodegenStatus::KeepCompiling
    }

    fn gen_opt_getconstant_path(&mut self) -> CodegenStatus {
        let const_cache_as_value = self.jit.get_arg(0);
        let ic: *const iseq_inline_constant_cache = const_cache_as_value.as_ptr();
        let idlist: *const ID = unsafe { (*ic).segments };

        // See vm_ic_hit_p(). The same conditions are checked in yjit_constant_ic_update().
        let ice = unsafe { (*ic).entry };
        if ice.is_null() {
            // In this case, leave a block that unconditionally side exits
            // for the interpreter to invalidate.
            return CodegenStatus::CantCompile;
        }

        // Make sure there is an exit for this block as the interpreter might want
        // to invalidate this block from yjit_constant_ic_update().
        self.jit_ensure_block_entry_exit();

        if !unsafe { (*ice).ic_cref }.is_null() {
            // Cache is keyed on a certain lexical scope. Use the interpreter's cache.
            let side_exit = self.get_side_exit(&self.ctx.clone());

            let inline_cache = self.asm.load(Opnd::const_ptr(ic as *const u8));

            // Call function to verify the cache. It doesn't allocate or call methods.
            let ret_val = self.asm.ccall(
                rb_vm_ic_hit_p as *const u8,
                vec![inline_cache, Opnd::mem(64, CFP, RUBY_OFFSET_CFP_EP)],
            );

            // Check the result. SysV only specifies one byte for _Bool return values,
            // so it's important we only check one bit to ignore the higher bits in the register.
            self.asm.test(ret_val, 1.into());
            let exit = counted_exit!(self.get_ocb(), side_exit, opt_getinlinecache_miss);
            self.asm.jz(exit);

            let inline_cache = self.asm.load(Opnd::const_ptr(ic as *const u8));

            let ic_entry = self
                .asm
                .load(Opnd::mem(64, inline_cache, RUBY_OFFSET_IC_ENTRY));

            let ic_entry_val = self
                .asm
                .load(Opnd::mem(64, ic_entry, RUBY_OFFSET_ICE_VALUE));

            // Push ic->entry->value
            let stack_top = self.ctx.stack_push(Type::Unknown);
            self.asm.store(stack_top, ic_entry_val);
        } else {
            // Optimize for single ractor mode.
            // FIXME: This leaks when st_insert raises NoMemoryError
            if !assume_single_ractor_mode(self) {
                return CodegenStatus::CantCompile;
            }

            // Invalidate output code on any constant writes associated with
            // constants referenced within the current block.
            assume_stable_constant_names(self, idlist);

            self.jit_putobject(unsafe { (*ice).value });
        }

        self.jump_to_next_insn();
        CodegenStatus::EndBlock
    }

    // Push the explicit block parameter onto the temporary stack. Part of the
    // interpreter's scheme for avoiding Proc allocations when delegating
    // explicit block parameters.
    fn gen_getblockparamproxy(&mut self) -> CodegenStatus {
        if !self.jit.at_current_insn() {
            self.defer_compilation();
            return CodegenStatus::EndBlock;
        }

        let starting_context = self.ctx.clone(); // make a copy for use with jit_chain_guard

        // A mirror of the interpreter code. Checking for the case
        // where it's pushing rb_block_param_proxy.
        let side_exit = self.get_side_exit(&self.ctx.clone());

        // EP level
        let level = self.jit.get_arg(1).as_u32();

        // Peek at the block handler so we can check whether it's nil
        let comptime_handler = self.jit.peek_at_block_handler(level);

        // When a block handler is present, it should always be a GC-guarded
        // pointer (VM_BH_ISEQ_BLOCK_P)
        if comptime_handler.as_u64() != 0 && comptime_handler.as_u64() & 0x3 != 0x1 {
            return CodegenStatus::CantCompile;
        }

        // Load environment pointer EP from CFP
        let ep_opnd = self.gen_get_ep(level);

        // Bail when VM_ENV_FLAGS(ep, VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM) is non zero
        let flag_check = Opnd::mem(
            64,
            ep_opnd,
            SIZEOF_VALUE_I32 * (VM_ENV_DATA_INDEX_FLAGS as i32),
        );
        self.asm
            .test(flag_check, VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM.into());
        let exit = counted_exit!(self.get_ocb(), side_exit, gbpp_block_param_modified);
        self.asm.jnz(exit);

        // Load the block handler for the current frame
        // note, VM_ASSERT(VM_ENV_LOCAL_P(ep))
        let block_handler = self.asm.load(Opnd::mem(
            64,
            ep_opnd,
            SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_SPECVAL,
        ));

        // Specialize compilation for the case where no block handler is present
        if comptime_handler.as_u64() == 0 {
            // Bail if there is a block handler
            self.asm.cmp(block_handler, Opnd::UImm(0));

            self.jit_chain_guard(&starting_context, JCC_JNZ, SEND_MAX_DEPTH, side_exit);

            self.jit_putobject(Qnil);
        } else {
            // Block handler is a tagged pointer. Look at the tag. 0x03 is from VM_BH_ISEQ_BLOCK_P().
            let block_handler = self.asm.and(block_handler, 0x3.into());

            // Bail unless VM_BH_ISEQ_BLOCK_P(bh). This also checks for null.
            self.asm.cmp(block_handler, 0x1.into());

            self.jit_chain_guard(&starting_context, JCC_JNZ, SEND_MAX_DEPTH, side_exit);

            // Push rb_block_param_proxy. It's a root, so no need to use jit_mov_gc_ptr.
            assert!(!unsafe { rb_block_param_proxy }.special_const_p());

            let top = self.ctx.stack_push(Type::BlockParamProxy);
            self.asm.mov(
                top,
                Opnd::const_ptr(unsafe { rb_block_param_proxy }.as_ptr()),
            );
        }

        self.jump_to_next_insn();

        CodegenStatus::EndBlock
    }

    fn gen_getblockparam(&mut self) -> CodegenStatus {
        // EP level
        let level = self.jit.get_arg(1).as_u32();

        // Save the PC and SP because we might allocate
        self.jit_prepare_routine_call();

        // A mirror of the interpreter code. Checking for the case
        // where it's pushing rb_block_param_proxy.
        let side_exit = self.get_side_exit(&self.ctx.clone());

        // Load environment pointer EP from CFP
        let ep_opnd = self.gen_get_ep(level);

        // Bail when VM_ENV_FLAGS(ep, VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM) is non zero
        let flag_check = Opnd::mem(
            64,
            ep_opnd,
            SIZEOF_VALUE_I32 * (VM_ENV_DATA_INDEX_FLAGS as i32),
        );
        // FIXME: This is testing bits in the same place that the WB check is testing.
        // We should combine these at some point
        self.asm
            .test(flag_check, VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM.into());

        // If the frame flag has been modified, then the actual proc value is
        // already in the EP and we should just use the value.
        let frame_flag_modified = self.asm.new_label("frame_flag_modified");
        self.asm.jnz(frame_flag_modified);

        // This instruction writes the block handler to the EP.  If we need to
        // fire a write barrier for the write, then exit (we'll let the
        // interpreter handle it so it can fire the write barrier).
        // flags & VM_ENV_FLAG_WB_REQUIRED
        let flags_opnd = Opnd::mem(
            64,
            ep_opnd,
            SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_FLAGS as i32,
        );
        self.asm.test(flags_opnd, VM_ENV_FLAG_WB_REQUIRED.into());

        // if (flags & VM_ENV_FLAG_WB_REQUIRED) != 0
        self.asm.jnz(side_exit);

        // Convert the block handler in to a proc
        // call rb_vm_bh_to_procval(const rb_execution_context_t *ec, VALUE block_handler)
        let proc = self.asm.ccall(
            rb_vm_bh_to_procval as *const u8,
            vec![
                EC,
                // The block handler for the current frame
                // note, VM_ASSERT(VM_ENV_LOCAL_P(ep))
                Opnd::mem(64, ep_opnd, SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_SPECVAL),
            ],
        );

        // Load environment pointer EP from CFP (again)
        let ep_opnd = self.gen_get_ep(level);

        // Write the value at the environment pointer
        let idx = self.jit.get_arg(0).as_i32();
        let offs = -(SIZEOF_VALUE_I32 * idx);
        self.asm.mov(Opnd::mem(64, ep_opnd, offs), proc);

        // Set the frame modified flag
        let flag_check = Opnd::mem(
            64,
            ep_opnd,
            SIZEOF_VALUE_I32 * (VM_ENV_DATA_INDEX_FLAGS as i32),
        );
        let modified_flag = self
            .asm
            .or(flag_check, VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM.into());
        self.asm.store(flag_check, modified_flag);

        self.asm.write_label(frame_flag_modified);

        // Push the proc on the stack
        let stack_ret = self.ctx.stack_push(Type::Unknown);
        let ep_opnd = self.gen_get_ep(level);
        self.asm.mov(stack_ret, Opnd::mem(64, ep_opnd, offs));

        CodegenStatus::KeepCompiling
    }

    fn gen_invokebuiltin(&mut self) -> CodegenStatus {
        let bf: *const rb_builtin_function = self.jit.get_arg(0).as_ptr();
        let bf_argc: usize = unsafe { (*bf).argc }.try_into().expect("non negative argc");

        // ec, self, and arguments
        if bf_argc + 2 > C_ARG_OPNDS.len() {
            return CodegenStatus::CantCompile;
        }

        // If the calls don't allocate, do they need up to date PC, SP?
        self.jit_prepare_routine_call();

        // Call the builtin func (ec, recv, arg1, arg2, ...)
        let mut args = vec![EC, Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SELF)];

        // Copy arguments from locals
        for i in 0..bf_argc {
            let stack_opnd = self.ctx.stack_opnd((bf_argc - i - 1) as i32);
            args.push(stack_opnd);
        }

        let val = self.asm.ccall(unsafe { (*bf).func_ptr } as *const u8, args);

        // Push the return value
        self.ctx.stack_pop(bf_argc);
        let stack_ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(stack_ret, val);

        CodegenStatus::KeepCompiling
    }

    // opt_invokebuiltin_delegate calls a builtin function, like
    // invokebuiltin does, but instead of taking arguments from the top of the
    // stack uses the argument locals (and self) from the current method.
    fn gen_opt_invokebuiltin_delegate(&mut self) -> CodegenStatus {
        let bf: *const rb_builtin_function = self.jit.get_arg(0).as_ptr();
        let bf_argc = unsafe { (*bf).argc };
        let start_index = self.jit.get_arg(1).as_i32();

        // ec, self, and arguments
        if bf_argc + 2 > (C_ARG_OPNDS.len() as i32) {
            return CodegenStatus::CantCompile;
        }

        // If the calls don't allocate, do they need up to date PC, SP?
        self.jit_prepare_routine_call();

        // Call the builtin func (ec, recv, arg1, arg2, ...)
        let mut args = vec![EC, Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SELF)];

        // Copy arguments from locals
        if bf_argc > 0 {
            // Load environment pointer EP from CFP
            let ep = self.asm.load(Opnd::mem(64, CFP, RUBY_OFFSET_CFP_EP));

            for i in 0..bf_argc {
                let table_size = unsafe { get_iseq_body_local_table_size(self.jit.iseq) };
                let offs: i32 =
                    -(table_size as i32) - (VM_ENV_DATA_SIZE as i32) + 1 + start_index + i;
                let local_opnd = Opnd::mem(64, ep, offs * SIZEOF_VALUE_I32);
                args.push(local_opnd);
            }
        }
        let val = self.asm.ccall(unsafe { (*bf).func_ptr } as *const u8, args);

        // Push the return value
        let stack_ret = self.ctx.stack_push(Type::Unknown);
        self.asm.mov(stack_ret, val);

        CodegenStatus::KeepCompiling
    }

    // :side-exit:
    // Get an exit for the current instruction in the outlined block. The code
    // for each instruction often begins with several guards before proceeding
    // to do work. When guards fail, an option we have is to exit to the
    // interpreter at an instruction boundary. The piece of code that takes
    // care of reconstructing interpreter state and exiting out of generated
    // code is called the side exit.
    //
    // No guards change the logic for reconstructing interpreter state at the
    // moment, so there is one unique side exit for each context. Note that
    // it's incorrect to jump to the side exit after any ctx stack push operations
    // since they change the logic required for reconstructing interpreter state.
    fn get_side_exit(&mut self, ctx: &Context) -> Target {
        match self.jit.side_exit_for_pc {
            None => {
                let exit_code = gen_outlined_exit(self.jit.pc, ctx, self.get_ocb());
                self.jit.side_exit_for_pc = Some(exit_code);
                exit_code.as_side_exit()
            }
            Some(code_ptr) => code_ptr.as_side_exit(),
        }
    }
}

/// Maps a YARV opcode to a code generation function (if supported)
fn get_gen_fn(opcode: VALUE) -> Option<InsnGenFn> {
    let VALUE(opcode) = opcode;
    let opcode = opcode as ruby_vminsn_type;
    assert!(opcode < VM_INSTRUCTION_SIZE);
    use crate::cruby::*;
    match opcode {
        YARVINSN_nop => Some(CodeGenerator::gen_nop),
        YARVINSN_pop => Some(CodeGenerator::gen_pop),
        YARVINSN_dup => Some(CodeGenerator::gen_dup),
        YARVINSN_dupn => Some(CodeGenerator::gen_dupn),
        YARVINSN_swap => Some(CodeGenerator::gen_swap),
        YARVINSN_putnil => Some(CodeGenerator::gen_putnil),
        YARVINSN_putobject => Some(CodeGenerator::gen_putobject),
        YARVINSN_putobject_INT2FIX_0_ => Some(CodeGenerator::gen_putobject_int2fix),
        YARVINSN_putobject_INT2FIX_1_ => Some(CodeGenerator::gen_putobject_int2fix),
        YARVINSN_putself => Some(CodeGenerator::gen_putself),
        YARVINSN_putspecialobject => Some(CodeGenerator::gen_putspecialobject),
        YARVINSN_setn => Some(CodeGenerator::gen_setn),
        YARVINSN_topn => Some(CodeGenerator::gen_topn),
        YARVINSN_adjuststack => Some(CodeGenerator::gen_adjuststack),

        YARVINSN_getlocal => Some(CodeGenerator::gen_getlocal),
        YARVINSN_getlocal_WC_0 => Some(CodeGenerator::gen_getlocal_wc0),
        YARVINSN_getlocal_WC_1 => Some(CodeGenerator::gen_getlocal_wc1),
        YARVINSN_setlocal => Some(CodeGenerator::gen_setlocal),
        YARVINSN_setlocal_WC_0 => Some(CodeGenerator::gen_setlocal_wc0),
        YARVINSN_setlocal_WC_1 => Some(CodeGenerator::gen_setlocal_wc1),
        YARVINSN_opt_plus => Some(CodeGenerator::gen_opt_plus),
        YARVINSN_opt_minus => Some(CodeGenerator::gen_opt_minus),
        YARVINSN_opt_and => Some(CodeGenerator::gen_opt_and),
        YARVINSN_opt_or => Some(CodeGenerator::gen_opt_or),
        YARVINSN_newhash => Some(CodeGenerator::gen_newhash),
        YARVINSN_duphash => Some(CodeGenerator::gen_duphash),
        YARVINSN_newarray => Some(CodeGenerator::gen_newarray),
        YARVINSN_duparray => Some(CodeGenerator::gen_duparray),
        YARVINSN_checktype => Some(CodeGenerator::gen_checktype),
        YARVINSN_opt_lt => Some(CodeGenerator::gen_opt_lt),
        YARVINSN_opt_le => Some(CodeGenerator::gen_opt_le),
        YARVINSN_opt_gt => Some(CodeGenerator::gen_opt_gt),
        YARVINSN_opt_ge => Some(CodeGenerator::gen_opt_ge),
        YARVINSN_opt_mod => Some(CodeGenerator::gen_opt_mod),
        YARVINSN_opt_str_freeze => Some(CodeGenerator::gen_opt_str_freeze),
        YARVINSN_opt_str_uminus => Some(CodeGenerator::gen_opt_str_uminus),
        YARVINSN_opt_newarray_max => Some(CodeGenerator::gen_opt_newarray_max),
        YARVINSN_opt_newarray_min => Some(CodeGenerator::gen_opt_newarray_min),
        YARVINSN_splatarray => Some(CodeGenerator::gen_splatarray),
        YARVINSN_concatarray => Some(CodeGenerator::gen_concatarray),
        YARVINSN_newrange => Some(CodeGenerator::gen_newrange),
        YARVINSN_putstring => Some(CodeGenerator::gen_putstring),
        YARVINSN_expandarray => Some(CodeGenerator::gen_expandarray),
        YARVINSN_defined => Some(CodeGenerator::gen_defined),
        YARVINSN_checkkeyword => Some(CodeGenerator::gen_checkkeyword),
        YARVINSN_concatstrings => Some(CodeGenerator::gen_concatstrings),
        YARVINSN_getinstancevariable => Some(CodeGenerator::gen_getinstancevariable),
        YARVINSN_setinstancevariable => Some(CodeGenerator::gen_setinstancevariable),

        YARVINSN_opt_eq => Some(CodeGenerator::gen_opt_eq),
        YARVINSN_opt_neq => Some(CodeGenerator::gen_opt_neq),
        YARVINSN_opt_aref => Some(CodeGenerator::gen_opt_aref),
        YARVINSN_opt_aset => Some(CodeGenerator::gen_opt_aset),
        YARVINSN_opt_mult => Some(CodeGenerator::gen_opt_mult),
        YARVINSN_opt_div => Some(CodeGenerator::gen_opt_div),
        YARVINSN_opt_ltlt => Some(CodeGenerator::gen_opt_ltlt),
        YARVINSN_opt_nil_p => Some(CodeGenerator::gen_opt_nil_p),
        YARVINSN_opt_empty_p => Some(CodeGenerator::gen_opt_empty_p),
        YARVINSN_opt_succ => Some(CodeGenerator::gen_opt_succ),
        YARVINSN_opt_not => Some(CodeGenerator::gen_opt_not),
        YARVINSN_opt_size => Some(CodeGenerator::gen_opt_size),
        YARVINSN_opt_length => Some(CodeGenerator::gen_opt_length),
        YARVINSN_opt_regexpmatch2 => Some(CodeGenerator::gen_opt_regexpmatch2),
        YARVINSN_getconstant => Some(CodeGenerator::gen_getconstant),
        YARVINSN_opt_getconstant_path => Some(CodeGenerator::gen_opt_getconstant_path),
        YARVINSN_invokebuiltin => Some(CodeGenerator::gen_invokebuiltin),
        YARVINSN_opt_invokebuiltin_delegate => Some(CodeGenerator::gen_opt_invokebuiltin_delegate),
        YARVINSN_opt_invokebuiltin_delegate_leave => {
            Some(CodeGenerator::gen_opt_invokebuiltin_delegate)
        }
        YARVINSN_opt_case_dispatch => Some(CodeGenerator::gen_opt_case_dispatch),
        YARVINSN_branchif => Some(CodeGenerator::gen_branchif),
        YARVINSN_branchunless => Some(CodeGenerator::gen_branchunless),
        YARVINSN_branchnil => Some(CodeGenerator::gen_branchnil),
        YARVINSN_jump => Some(CodeGenerator::gen_jump),

        YARVINSN_getblockparamproxy => Some(CodeGenerator::gen_getblockparamproxy),
        YARVINSN_getblockparam => Some(CodeGenerator::gen_getblockparam),
        YARVINSN_opt_send_without_block => Some(CodeGenerator::gen_opt_send_without_block),
        YARVINSN_send => Some(CodeGenerator::gen_send),
        YARVINSN_invokeblock => Some(CodeGenerator::gen_invokeblock),
        YARVINSN_invokesuper => Some(CodeGenerator::gen_invokesuper),
        YARVINSN_leave => Some(CodeGenerator::gen_leave),

        YARVINSN_getglobal => Some(CodeGenerator::gen_getglobal),
        YARVINSN_setglobal => Some(CodeGenerator::gen_setglobal),
        YARVINSN_anytostring => Some(CodeGenerator::gen_anytostring),
        YARVINSN_objtostring => Some(CodeGenerator::gen_objtostring),
        YARVINSN_intern => Some(CodeGenerator::gen_intern),
        YARVINSN_toregexp => Some(CodeGenerator::gen_toregexp),
        YARVINSN_getspecial => Some(CodeGenerator::gen_getspecial),
        YARVINSN_getclassvariable => Some(CodeGenerator::gen_getclassvariable),
        YARVINSN_setclassvariable => Some(CodeGenerator::gen_setclassvariable),

        // Unimplemented opcode, YJIT won't generate code for this yet
        _ => None,
    }
}

// Check if we know how to codegen for a particular cfunc method
fn lookup_cfunc_codegen(def: *const rb_method_definition_t) -> Option<globals::MethodGenFn> {
    let method_serial = unsafe { get_def_method_serial(def) };

    CodegenGlobals::look_up_codegen_method(method_serial)
}

// Is anyone listening for :c_call and :c_return event currently?
fn c_method_tracing_currently_enabled(jit: &JITState) -> bool {
    // Defer to C implementation in yjit.c
    unsafe {
        rb_c_method_tracing_currently_enabled(jit.ec.unwrap() as *mut rb_execution_context_struct)
    }
}

// Similar to args_kw_argv_to_hash. It is called at runtime from within the
// generated assembly to build a Ruby hash of the passed keyword arguments. The
// keys are the Symbol objects associated with the keywords and the values are
// the actual values. In the representation, both keys and values are VALUEs.
unsafe extern "C" fn build_kwhash(ci: *const rb_callinfo, sp: *const VALUE) -> VALUE {
    let kw_arg = vm_ci_kwarg(ci);
    let kw_len: usize = get_cikw_keyword_len(kw_arg).try_into().unwrap();
    let hash = rb_hash_new_with_size(kw_len as u64);

    for kwarg_idx in 0..kw_len {
        let key = get_cikw_keywords_idx(kw_arg, kwarg_idx.try_into().unwrap());
        let val = sp.sub(kw_len).add(kwarg_idx).read();
        rb_hash_aset(hash, key, val);
    }
    hash
}

// SpecVal is a single value in an iseq invocation's environment on the stack,
// at sp[-2]. Depending on the frame type, it can serve different purposes,
// which are covered here by enum variants.
enum SpecVal {
    None,
    BlockISeq(IseqPtr),
    BlockParamProxy,
    PrevEP(*const VALUE),
    PrevEPOpnd(Opnd),
}

struct ControlFrame {
    recv: Opnd,
    sp: Opnd,
    iseq: Option<IseqPtr>,
    pc: Option<u64>,
    frame_type: u32,
    specval: SpecVal,
    cme: *const rb_callable_method_entry_t,
    local_size: i32,
}

// up to 5 different classes, and embedded or not for each
pub const GET_IVAR_MAX_DEPTH: i32 = 10;

// up to 5 different classes, and embedded or not for each
pub const SET_IVAR_MAX_DEPTH: i32 = 10;

// hashes and arrays
pub const OPT_AREF_MAX_CHAIN_DEPTH: i32 = 2;

// up to 5 different classes
pub const SEND_MAX_DEPTH: i32 = 5;

// up to 20 different methods for send
pub const SEND_MAX_CHAIN_DEPTH: i32 = 20;

// up to 20 different offsets for case-when
pub const CASE_WHEN_MAX_DEPTH: i32 = 20;

// Conditional move operation used by comparison operators
type CmovFn = fn(cb: &mut Assembler, opnd0: Opnd, opnd1: Opnd) -> Opnd;

/// For implementing global code invalidation. A position in the inline
/// codeblock to patch into a JMP rel32 which jumps into some code in
/// the outlined codeblock to exit to the interpreter.
pub struct CodepagePatch {
    pub inline_patch_pos: CodePtr,
    pub outlined_target_pos: CodePtr,
}

#[cfg(test)]
mod tests {

    use super::*;

    fn setup_codegen() -> (CodeGenerator, CodeBlock) {
        let blockid = BlockId {
            iseq: ptr::null(),
            idx: 0,
        };
        let cb = CodeBlock::new_dummy(256 * 1024);
        let block = Block::make_ref(blockid, &Context::default(), cb.get_write_ptr());
        (
            CodeGenerator::new(
                JITState::new(&block),
                Context::default(),
                Assembler::new(),
                OutlinedCb::wrap(CodeBlock::new_dummy(256 * 1024)),
            ),
            cb,
        )
    }

    #[test]
    fn test_gen_leave_exit() {
        let (mut gen, _) = setup_codegen();
        gen_leave_exit(&mut gen.ocb);
        assert!(gen.ocb.unwrap().get_write_pos() > 0);
    }

    #[test]
    fn test_gen_exit() {
        let (mut gen, mut cb) = setup_codegen();
        gen_exit(std::ptr::null_mut::<VALUE>(), &gen.ctx, &mut gen.asm);
        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_get_side_exit() {
        let (mut gen, _) = setup_codegen();
        gen.get_side_exit(&gen.ctx.clone());
        assert!(gen.ocb.unwrap().get_write_pos() > 0);
    }

    #[test]
    fn test_gen_check_ints() {
        let (mut gen, _cb) = setup_codegen();
        let side_exit = gen.ocb.unwrap().get_write_ptr().as_side_exit();
        gen_check_ints(&mut gen.asm, side_exit);
    }

    #[test]
    fn test_gen_nop() {
        let (mut gen, mut cb) = setup_codegen();
        let status = gen.gen_nop();
        gen.asm.compile(&mut cb);

        assert_eq!(status, CodegenStatus::KeepCompiling);
        assert_eq!(gen.ctx.diff(&Context::default()), TypeDiff::Compatible(0));
        assert_eq!(cb.get_write_pos(), 0);
    }

    #[test]
    fn test_gen_pop() {
        let (mut gen, _cb) = setup_codegen();
        gen.ctx.stack_push(Type::Fixnum);
        let status = gen.gen_pop();

        assert_eq!(status, CodegenStatus::KeepCompiling);
        assert_eq!(gen.ctx.diff(&Context::default()), TypeDiff::Compatible(0));
    }

    #[test]
    fn test_gen_dup() {
        let (mut gen, mut cb) = setup_codegen();
        gen.ctx.stack_push(Type::Fixnum);
        let status = gen.gen_dup();

        assert_eq!(status, CodegenStatus::KeepCompiling);

        // Did we duplicate the type information for the Fixnum type?
        assert_eq!(Type::Fixnum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));
        assert_eq!(Type::Fixnum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(1)));

        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0); // Write some movs
    }

    #[test]
    fn test_gen_dupn() {
        let (mut gen, mut cb) = setup_codegen();
        gen.ctx.stack_push(Type::Fixnum);
        gen.ctx.stack_push(Type::Flonum);

        let mut value_array: [u64; 2] = [0, 2]; // We only compile for n == 2
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        gen.jit.pc = pc;

        let status = gen.gen_dupn();

        assert_eq!(status, CodegenStatus::KeepCompiling);

        assert_eq!(Type::Fixnum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(3)));
        assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(2)));
        assert_eq!(Type::Fixnum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(1)));
        assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));

        // TODO: this is writing zero bytes on x86. Why?
        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0); // Write some movs
    }

    #[test]
    fn test_gen_swap() {
        let (mut gen, _cb) = setup_codegen();
        gen.ctx.stack_push(Type::Fixnum);
        gen.ctx.stack_push(Type::Flonum);

        let status = gen.gen_swap();

        let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));
        let (_, tmp_type_next) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(1));

        assert_eq!(status, CodegenStatus::KeepCompiling);
        assert_eq!(tmp_type_top, Type::Fixnum);
        assert_eq!(tmp_type_next, Type::Flonum);
    }

    #[test]
    fn test_putnil() {
        let (mut gen, mut cb) = setup_codegen();
        let status = gen.gen_putnil();

        let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

        assert_eq!(status, CodegenStatus::KeepCompiling);
        assert_eq!(tmp_type_top, Type::Nil);
        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_putobject_qtrue() {
        // Test gen_putobject with Qtrue
        let (mut gen, mut cb) = setup_codegen();

        let mut value_array: [u64; 2] = [0, Qtrue.into()];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        gen.jit.pc = pc;

        let status = gen.gen_putobject();

        let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

        assert_eq!(status, CodegenStatus::KeepCompiling);
        assert_eq!(tmp_type_top, Type::True);
        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_putobject_fixnum() {
        // Test gen_putobject with a Fixnum to test another conditional branch
        let (mut gen, mut cb) = setup_codegen();

        // The Fixnum 7 is encoded as 7 * 2 + 1, or 15
        let mut value_array: [u64; 2] = [0, 15];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        gen.jit.pc = pc;

        let status = gen.gen_putobject();

        let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

        assert_eq!(status, CodegenStatus::KeepCompiling);
        assert_eq!(tmp_type_top, Type::Fixnum);
        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_int2fix() {
        let (mut gen, _cb) = setup_codegen();
        gen.jit.opcode = YARVINSN_putobject_INT2FIX_0_.into_usize();
        let status = gen.gen_putobject_int2fix();

        let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

        // Right now we're not testing the generated machine code to make sure a literal 1 or 0 was pushed. I've checked locally.
        assert_eq!(status, CodegenStatus::KeepCompiling);
        assert_eq!(tmp_type_top, Type::Fixnum);
    }

    #[test]
    fn test_putself() {
        let (mut gen, mut cb) = setup_codegen();
        let status = gen.gen_putself();

        assert_eq!(status, CodegenStatus::KeepCompiling);
        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_gen_setn() {
        let (mut gen, mut cb) = setup_codegen();
        gen.ctx.stack_push(Type::Fixnum);
        gen.ctx.stack_push(Type::Flonum);
        gen.ctx.stack_push(Type::CString);

        let mut value_array: [u64; 2] = [0, 2];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        gen.jit.pc = pc;

        let status = gen.gen_setn();

        assert_eq!(status, CodegenStatus::KeepCompiling);

        assert_eq!(Type::CString, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(2)));
        assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(1)));
        assert_eq!(Type::CString, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));

        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_gen_topn() {
        let (mut gen, mut cb) = setup_codegen();
        gen.ctx.stack_push(Type::Flonum);
        gen.ctx.stack_push(Type::CString);

        let mut value_array: [u64; 2] = [0, 1];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        gen.jit.pc = pc;

        let status = gen.gen_topn();

        assert_eq!(status, CodegenStatus::KeepCompiling);

        assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(2)));
        assert_eq!(Type::CString, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(1)));
        assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));

        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() > 0); // Write some movs
    }

    #[test]
    fn test_gen_adjuststack() {
        let (mut gen, mut cb) = setup_codegen();
        gen.ctx.stack_push(Type::Flonum);
        gen.ctx.stack_push(Type::CString);
        gen.ctx.stack_push(Type::Fixnum);

        let mut value_array: [u64; 3] = [0, 2, 0];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        gen.jit.pc = pc;

        let status = gen.gen_adjuststack();

        assert_eq!(status, CodegenStatus::KeepCompiling);

        assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));

        gen.asm.compile(&mut cb);
        assert!(cb.get_write_pos() == 0); // No instructions written
    }

    #[test]
    fn test_gen_leave() {
        let (mut gen, _cb) = setup_codegen();
        // Push return value
        gen.ctx.stack_push(Type::Fixnum);
        gen.gen_leave();
    }
}

// We use the YARV bytecode constants which have a CRuby-style name
#![allow(non_upper_case_globals)]

use std::os::raw::c_uint;

pub use crate::virtualmem::CodePtr;

use crate::{
    asm::{CodeBlock, OutlinedCb},
    backend::ir::{Assembler, Opnd, Target, CFP, EC, SP},
    bbv::limit_block_versions,
    codegen::{generator::{CodeGenerator, CodegenStatus}, globals::CodegenGlobals},
    core::{free_block, verify_blockid},
    cruby::{
        get_cikw_keyword_len, get_cikw_keywords_idx, get_def_method_serial, get_iseq_encoded_size,
        insn_len, insn_name, rb_c_method_tracing_currently_enabled, rb_callinfo,
        rb_execution_context_struct, rb_hash_aset, rb_hash_new_with_size, rb_iseq_opcode_at_pc,
        rb_iseq_pc_at_idx, rb_method_definition_t, vm_ci_kwarg, EcPtr, IseqPtr, Qundef,
        YARVINSN_opt_getconstant_path, RUBY_OFFSET_CFP_PC, RUBY_OFFSET_CFP_SP,
        RUBY_OFFSET_EC_INTERRUPT_FLAG, VALUE,
    },
    dev::{
        options::{get_option, get_option_ref},
        stats::{ptr_to_counter, rb_yjit_count_side_exit_op, rb_yjit_record_exit_stack},
    },
    gen_counter_incr,
    meta::{
        block::{Block, BlockId, BlockRef},
        context::{verify_ctx, Context},
        jit_state::JITState,
    },
    utils::{iseq_get_location, print_str, IntoUsize},
};


pub mod generator;
pub mod globals;
pub mod method_overrides;

/// Code generation function signature
type InsnGenFn = fn(code_generator: &mut CodeGenerator) -> CodegenStatus;


// Still a work in progress.
// Trying to move things so they are in places that make sense.
// Eventually we will get to a point where entry is just getting
// some struct a calling a method on it.

impl CodeGenerator {
    // Save the incremented PC on the CFP
    // This is necessary when callees can raise or allocate
    fn jit_save_pc(&mut self) {
        let pc: *mut VALUE = self.jit.get_pc();
        let ptr: *mut VALUE = unsafe {
            let cur_insn_len = insn_len(self.jit.get_opcode()) as isize;
            pc.offset(cur_insn_len)
        };

        self.asm.comment("save PC to CFP");
        self.asm.mov(
            Opnd::mem(64, CFP, RUBY_OFFSET_CFP_PC),
            Opnd::const_ptr(ptr as *const u8),
        );
    }

    /// Save the current SP on the CFP
    /// This realigns the interpreter SP with the JIT SP
    /// Note: this will change the current value of REG_SP,
    ///       which could invalidate memory operands
    fn gen_save_sp(&mut self) {
        if self.ctx.get_sp_offset() != 0 {
            self.asm.comment("save SP to CFP");
            let stack_pointer = self.ctx.sp_opnd(0);
            let sp_addr = self.asm.lea(stack_pointer);
            self.asm.mov(SP, sp_addr);
            let cfp_sp_opnd = Opnd::mem(64, CFP, RUBY_OFFSET_CFP_SP);
            self.asm.mov(cfp_sp_opnd, SP);
            self.ctx.set_sp_offset(0);
        }
    }

    /// Record the current codeblock write position for rewriting into a jump into
    /// the outlined block later. Used to implement global code invalidation.
    fn record_global_inval_patch(&mut self, outline_block_target_pos: CodePtr) {
        self.asm.pad_inval_patch();
        self.asm.pos_marker(move |code_ptr| {
            CodegenGlobals::push_global_inval_patch(code_ptr, outline_block_target_pos);
        });
    }

    /// Generate an exit to return to the interpreter
    fn gen_exit(&mut self, exit_pc: *mut VALUE, asm: &mut Assembler, ctx: &Context) {
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
    fn gen_outlined_exit(&mut self, exit_pc: *mut VALUE, ctx: &Context) -> CodePtr {
        let cb = self.ocb.unwrap();
        let exit_code = cb.get_write_ptr();
        let mut asm = Assembler::new();
        drop(cb);
        self.gen_exit(exit_pc, &mut asm, ctx);
        let cb = self.ocb.unwrap();
        asm.compile(cb);

        exit_code
    }

    // Generate code to check for interrupts and take a side-exit.
    // Warning: this function clobbers REG0
    fn gen_check_ints(&mut self, side_exit: Target) {
        // Check for interrupts
        // see RUBY_VM_CHECK_INTS(ec) macro
        self.asm.comment("RUBY_VM_CHECK_INTS(ec)");

        // Not checking interrupt_mask since it's zero outside finalize_deferred_heap_pages,
        // signal_exec, or rb_postponed_job_flush.
        let interrupt_flag = self
            .asm
            .load(Opnd::mem(32, EC, RUBY_OFFSET_EC_INTERRUPT_FLAG));
        self.asm.test(interrupt_flag, interrupt_flag);

        self.asm.jnz(side_exit);
    }

    // Compile a sequence of bytecode instructions for a given basic block version.
    // Part of gen_block_version().
    // Note: this function will mutate its context while generating code,
    //       but the input start_ctx argument should remain immutable.
    pub fn gen_single_block(
        &mut self,
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

        // TODO: Probably don't need to do this.
        // Initialize a JIT state object
        let mut jit = JITState::new(&blockref);
        jit.iseq = blockid.iseq;
        jit.ec = Some(ec);
        self.jit = jit;

        self.debug_record_block_comment(blockid);

        // For each instruction to compile
        // NOTE: could rewrite this loop with a std::iter::Iterator
        while insn_idx < iseq_size {
            let starting_ctx = self.ctx.clone();
            // Get the current pc and opcode
            let pc = unsafe { rb_iseq_pc_at_idx(iseq, insn_idx) };
            // try_into() call below is unfortunate. Maybe pick i32 instead of usize for opcodes.
            let opcode: usize = unsafe { rb_iseq_opcode_at_pc(iseq, pc) }
                .try_into()
                .unwrap();

            // We need opt_getconstant_path to be in a block all on its own. Cut the block short
            // if we run into it. This is necessary because we want to invalidate based on the
            // instruction's index.
            if opcode == YARVINSN_opt_getconstant_path.into_usize() && insn_idx > starting_insn_idx
            {
                // TODO: JIMMY Need a code generator
                self.jump_to_next_insn();
                break;
            }

            // Set the current instruction
            self.jit.insn_idx = insn_idx;
            self.jit.opcode = opcode;
            self.jit.pc = pc;
            self.jit.side_exit_for_pc = None;

            // If previous instruction requested to record the boundary
            if self.jit.record_boundary_patch_point {
                // Generate an exit to this instruction and record it
                let exit_pos = old_gen_outlined_exit(self.jit.pc, &self.ctx, &mut self.ocb);
                old_record_global_inval_patch(&mut self.asm, exit_pos);
                self.jit.record_boundary_patch_point = false;
            }

            // In debug mode, verify our existing assumption
            if cfg!(debug_assertions) && get_option!(verify_ctx) && self.jit.at_current_insn() {
                verify_ctx(&self.jit, &self.ctx);
            }

            // Lookup the codegen function for this instruction
            let mut status = CodegenStatus::CantCompile;
            if let Some(gen_fn) = get_gen_fn(VALUE(opcode)) {
                // :count-placement:
                // Count bytecode instructions that execute in generated code.
                // Note that the increment happens even when the output takes side exit.
                gen_counter_incr!(self.asm, exec_instruction);

                // Add a comment for the name of the YARV instruction
                self.asm.comment(&format!("Insn: {}", insn_name(opcode)));

                // If requested, dump instructions for debugging
                if get_option!(dump_insns) {
                    println!("compiling {}", insn_name(opcode));
                    print_str(&mut self.asm, &format!("executing {}", insn_name(opcode)));
                }

                // Call the code generation function
                status = gen_fn(self);
            }

            // If we can't compile this instruction
            // exit to the interpreter and stop compiling
            if status == CodegenStatus::CantCompile {
                if get_option!(dump_insns) {
                    println!("can't compile {}", insn_name(opcode));
                }

                let mut block = self.jit.block.borrow_mut();

                // We are using starting_ctx so that if code_generator.ctx got mutated
                // it won't matter. If you write to the stack to you could still get errors,
                // but not from simple push and pops
                old_gen_exit(self.jit.pc, &starting_ctx, &mut self.asm);

                // If this is the first instruction in the block, then we can use
                // the exit for block->entry_exit.
                if insn_idx == block.get_blockid().idx {
                    block.entry_exit = Some(block.get_start_addr());
                }

                break;
            }

            // For now, reset the chain depth after each instruction as only the
            // first instruction in the block can concern itself with the depth.
            self.ctx.reset_chain_depth();

            // Move to the next instruction to compile
            insn_idx += insn_len(opcode);

            // If the instruction terminates this block
            if status == CodegenStatus::EndBlock {
                break;
            }
        }

        // Finish filling out the block
        {
            let ocb = self.swap_ocb();
            CodegenGlobals::set_outlined_cb(ocb);

            let asm = self.swap_asm();
            let mut block = self.jit.block.borrow_mut();
            if block.entry_exit.is_some() {
                self.asm.pad_inval_patch();
            }

            // Compile code into the code block
            let gc_offsets = asm.compile(cb);

            // Add the GC offsets to the block
            block.set_gc_obj_offsets(gc_offsets);

            // Set CME dependencies to the block
            block.set_cme_dependencies(&self.jit.cme_dependencies);

            // Set outgoing branches to the block
            block.set_outgoing(&self.jit.outgoing);

            // Mark the end position of the block
            block.set_end_addr(cb.get_write_ptr());

            // Store the index of the last instruction in the block
            block.set_end_idx(insn_idx);
        }

        // We currently can't handle cases where the request is for a block that
        // doesn't go to the next instruction.
        assert!(!self.jit.record_boundary_patch_point);

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
}

impl CodeGenerator {
    fn debug_record_block_comment(&mut self, blockid: BlockId) {
        #[cfg(feature = "disasm")]
        if let Some(_) = get_option_ref!(dump_disasm) {
            let blockid_idx = blockid.idx;
            let chain_depth = match self.ctx.get_chain_depth() {
                0 => String::new(),
                depth => format!(", chain_depth: {}", depth),
            };
            let location = iseq_get_location(blockid.iseq, blockid_idx);
            self.asm.comment(&format!(
                "Block: {} (ISEQ offset: {}{})",
                location, blockid_idx, chain_depth
            ));
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


/// Record the current codeblock write position for rewriting into a jump into
/// the outlined block later. Used to implement global code invalidation.
fn old_record_global_inval_patch(asm: &mut Assembler, outline_block_target_pos: CodePtr) {
    asm.pad_inval_patch();
    asm.pos_marker(move |code_ptr| {
        CodegenGlobals::push_global_inval_patch(code_ptr, outline_block_target_pos);
    });
}

/// Generate an exit to return to the interpreter
fn old_gen_exit(exit_pc: *mut VALUE, ctx: &Context, asm: &mut Assembler) {
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
fn old_gen_outlined_exit(exit_pc: *mut VALUE, ctx: &Context, ocb: &mut OutlinedCb) -> CodePtr {
    let cb = ocb.unwrap();
    let exit_code = cb.get_write_ptr();
    let mut asm = Assembler::new();

    old_gen_exit(exit_pc, ctx, &mut asm);

    asm.compile(cb);

    exit_code
}

// Generate a runtime guard that ensures the PC is at the expected
// instruction index in the iseq, otherwise takes a side-exit.
// This is to handle the situation of optional parameters.
// When a function with optional parameters is called, the entry
// PC for the method isn't necessarily 0.
pub fn old_gen_pc_guard(asm: &mut Assembler, iseq: IseqPtr, insn_idx: u32) {
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

#[cfg(test)]
mod tests;
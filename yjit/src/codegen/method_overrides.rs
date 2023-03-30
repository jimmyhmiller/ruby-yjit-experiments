use crate::{
    backend::ir::{Opnd, EC},
    counted_exit,
    cruby::{
        get_cme_def_type, idRespond_to_missing, rb_cArray, rb_cBasicObject, rb_cInteger,
        rb_cModule, rb_cNilClass, rb_cString, rb_cSymbol, rb_cThread,
        rb_callable_method_entry_or_negative, rb_callable_method_entry_t, rb_callinfo, rb_mKernel,
        rb_obj_class, rb_obj_is_kind_of, rb_singleton_class, rb_str_buf_append, rb_str_bytesize,
        rb_str_dup, rb_sym2id, rb_yjit_str_simple_append, IseqPtr, Qfalse, Qtrue,
        METHOD_ENTRY_VISI, METHOD_VISI_PUBLIC, METHOD_VISI_UNDEF, RB_TYPE_P, RUBY_ENCODING_MASK,
        RUBY_FL_FREEZE, RUBY_IMMEDIATE_MASK, RUBY_OFFSET_EC_THREAD_PTR, RUBY_OFFSET_RBASIC_FLAGS,
        RUBY_OFFSET_RSTRING_AS_HEAP_LEN, RUBY_OFFSET_RSTRING_EMBED_LEN, RUBY_OFFSET_THREAD_SELF,
        RUBY_T_CLASS, RUBY_T_MODULE, RUBY_T_STRING, SIZEOF_VALUE_I32, VALUE, VM_BLOCK_HANDLER_NONE,
        VM_ENV_DATA_INDEX_SPECVAL, VM_METHOD_TYPE_REFINED, VM_METHOD_TYPE_UNDEF,
    },
    meta::{
        context::{Type, YARVOpnd},
        invariants::{assume_method_basic_definition, assume_method_lookup_stable},
    },
};

use super::globals::CodegenGlobals;
use crate::codegen::generator::CodeGenerator;

impl CodeGenerator {
    pub fn init_overrides(instance: &mut CodegenGlobals) {
        unsafe {
            // Specialization for C methods. See yjit_reg_method() for details.
            instance.yjit_reg_method(rb_cBasicObject, "!", CodeGenerator::jit_rb_obj_not);

            instance.yjit_reg_method(rb_cNilClass, "nil?", CodeGenerator::jit_rb_true);
            instance.yjit_reg_method(rb_mKernel, "nil?", CodeGenerator::jit_rb_false);
            instance.yjit_reg_method(rb_mKernel, "is_a?", CodeGenerator::jit_rb_kernel_is_a);
            instance.yjit_reg_method(rb_mKernel, "kind_of?", CodeGenerator::jit_rb_kernel_is_a);
            instance.yjit_reg_method(
                rb_mKernel,
                "instance_of?",
                CodeGenerator::jit_rb_kernel_instance_of,
            );

            instance.yjit_reg_method(rb_cBasicObject, "==", CodeGenerator::jit_rb_obj_equal);
            instance.yjit_reg_method(rb_cBasicObject, "equal?", CodeGenerator::jit_rb_obj_equal);
            instance.yjit_reg_method(rb_cBasicObject, "!=", CodeGenerator::jit_rb_obj_not_equal);
            instance.yjit_reg_method(rb_mKernel, "eql?", CodeGenerator::jit_rb_obj_equal);
            instance.yjit_reg_method(rb_cModule, "==", CodeGenerator::jit_rb_obj_equal);
            instance.yjit_reg_method(rb_cModule, "===", CodeGenerator::jit_rb_mod_eqq);
            instance.yjit_reg_method(rb_cSymbol, "==", CodeGenerator::jit_rb_obj_equal);
            instance.yjit_reg_method(rb_cSymbol, "===", CodeGenerator::jit_rb_obj_equal);
            instance.yjit_reg_method(rb_cInteger, "==", CodeGenerator::jit_rb_int_equal);
            instance.yjit_reg_method(rb_cInteger, "===", CodeGenerator::jit_rb_int_equal);

            // rb_str_to_s() methods in string.c
            instance.yjit_reg_method(rb_cString, "empty?", CodeGenerator::jit_rb_str_empty_p);
            instance.yjit_reg_method(rb_cString, "to_s", CodeGenerator::jit_rb_str_to_s);
            instance.yjit_reg_method(rb_cString, "to_str", CodeGenerator::jit_rb_str_to_s);
            instance.yjit_reg_method(rb_cString, "bytesize", CodeGenerator::jit_rb_str_bytesize);
            instance.yjit_reg_method(rb_cString, "<<", CodeGenerator::jit_rb_str_concat);
            instance.yjit_reg_method(rb_cString, "+@", CodeGenerator::jit_rb_str_uplus);

            // rb_ary_empty_p() method in array.c
            instance.yjit_reg_method(rb_cArray, "empty?", CodeGenerator::jit_rb_ary_empty_p);

            instance.yjit_reg_method(rb_mKernel, "respond_to?", CodeGenerator::jit_obj_respond_to);
            instance.yjit_reg_method(
                rb_mKernel,
                "block_given?",
                CodeGenerator::jit_rb_f_block_given_p,
            );

            // Thread.current
            instance.yjit_reg_method(
                rb_singleton_class(rb_cThread),
                "current",
                CodeGenerator::jit_thread_s_current,
            );
        }
    }

    // Codegen for rb_obj_not().
    // Note, caller is responsible for generating all the right guards, including
    // arity guards.
    fn jit_rb_obj_not(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        let recv_opnd = self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0));

        match recv_opnd.known_truthy() {
            Some(false) => {
                self.asm.comment("rb_obj_not(nil_or_false)");
                self.ctx.stack_pop(1);
                let out_opnd = self.ctx.stack_push(Type::True);
                self.asm.mov(out_opnd, Qtrue.into());
            }
            Some(true) => {
                // Note: recv_opnd != Type::Nil && recv_opnd != Type::False.
                self.asm.comment("rb_obj_not(truthy)");
                self.ctx.stack_pop(1);
                let out_opnd = self.ctx.stack_push(Type::False);
                self.asm.mov(out_opnd, Qfalse.into());
            }
            _ => {
                return false;
            }
        }

        true
    }

    // Codegen for rb_true()
    fn jit_rb_true(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        self.asm.comment("nil? == true");
        self.ctx.stack_pop(1);
        let stack_ret = self.ctx.stack_push(Type::True);
        self.asm.mov(stack_ret, Qtrue.into());
        true
    }

    // Codegen for rb_false()
    fn jit_rb_false(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        self.asm.comment("nil? == false");
        self.ctx.stack_pop(1);
        let stack_ret = self.ctx.stack_push(Type::False);
        self.asm.mov(stack_ret, Qfalse.into());
        true
    }

    /// Codegen for Kernel#is_a?
    fn jit_rb_kernel_is_a(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        argc: i32,
        known_recv_class: *const VALUE,
    ) -> bool {
        if argc != 1 {
            return false;
        }

        // If this is a super call we might not know the class
        if known_recv_class.is_null() {
            return false;
        }

        // Important note: The output code will simply `return true/false`.
        // Correctness follows from:
        //  - `known_recv_class` implies there is a guard scheduled before here
        //    for a particular `CLASS_OF(lhs)`.
        //  - We guard that rhs is identical to the compile-time sample
        //  - In general, for any two Class instances A, B, `A < B` does not change at runtime.
        //    Class#superclass is stable.

        let sample_rhs = self.jit.peek_at_stack(&self.ctx, 0);
        let sample_lhs = self.jit.peek_at_stack(&self.ctx, 1);

        // We are not allowing module here because the module hierachy can change at runtime.
        if !unsafe { RB_TYPE_P(sample_rhs, RUBY_T_CLASS) } {
            return false;
        }
        let sample_is_a = unsafe { rb_obj_is_kind_of(sample_lhs, sample_rhs) == Qtrue };

        let side_exit = self.get_side_exit(&self.ctx.clone());
        self.asm.comment("Kernel#is_a?");
        self.asm.cmp(self.ctx.stack_opnd(0), sample_rhs.into());
        let exit = counted_exit!(self.get_ocb(), side_exit, send_is_a_class_mismatch);
        self.asm.jne(exit);

        self.ctx.stack_pop(2);

        if sample_is_a {
            let stack_ret = self.ctx.stack_push(Type::True);
            self.asm.mov(stack_ret, Qtrue.into());
        } else {
            let stack_ret = self.ctx.stack_push(Type::False);
            self.asm.mov(stack_ret, Qfalse.into());
        }
        true
    }

    /// Codegen for Kernel#instance_of?
    fn jit_rb_kernel_instance_of(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        argc: i32,
        known_recv_class: *const VALUE,
    ) -> bool {
        if argc != 1 {
            return false;
        }

        // If this is a super call we might not know the class
        if known_recv_class.is_null() {
            return false;
        }

        // Important note: The output code will simply `return true/false`.
        // Correctness follows from:
        //  - `known_recv_class` implies there is a guard scheduled before here
        //    for a particular `CLASS_OF(lhs)`.
        //  - We guard that rhs is identical to the compile-time sample
        //  - For a particular `CLASS_OF(lhs)`, `rb_obj_class(lhs)` does not change.
        //    (because for any singleton class `s`, `s.superclass.equal?(s.attached_object.class)`)

        let sample_rhs = self.jit.peek_at_stack(&self.ctx, 0);
        let sample_lhs = self.jit.peek_at_stack(&self.ctx, 1);

        // Filters out cases where the C implementation raises
        if unsafe { !(RB_TYPE_P(sample_rhs, RUBY_T_CLASS) || RB_TYPE_P(sample_rhs, RUBY_T_MODULE)) }
        {
            return false;
        }

        // We need to grab the class here to deal with singleton classes.
        // Instance of grabs the "real class" of the object rather than the
        // singleton class.
        let sample_lhs_real_class = unsafe { rb_obj_class(sample_lhs) };

        let sample_instance_of = sample_lhs_real_class == sample_rhs;

        let side_exit = self.get_side_exit(&self.ctx.clone());
        self.asm.comment("Kernel#instance_of?");
        self.asm.cmp(self.ctx.stack_opnd(0), sample_rhs.into());
        let exit = counted_exit!(self.get_ocb(), side_exit, send_instance_of_class_mismatch);
        self.asm.jne(exit);

        self.ctx.stack_pop(2);

        if sample_instance_of {
            let stack_ret = self.ctx.stack_push(Type::True);
            self.asm.mov(stack_ret, Qtrue.into());
        } else {
            let stack_ret = self.ctx.stack_push(Type::False);
            self.asm.mov(stack_ret, Qfalse.into());
        }
        true
    }

    fn jit_rb_mod_eqq(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        if argc != 1 {
            return false;
        }

        self.asm.comment("Module#===");
        // By being here, we know that the receiver is a T_MODULE or a T_CLASS, because Module#=== can
        // only live on these objects. With that, we can call rb_obj_is_kind_of() without
        // jit_prepare_routine_call() or a control frame push because it can't raise, allocate, or call
        // Ruby methods with these inputs.
        // Note the difference in approach from Kernel#is_a? because we don't get a free guard for the
        // right hand side.
        let lhs = self.ctx.stack_opnd(1); // the module
        let rhs = self.ctx.stack_opnd(0);
        let ret = self
            .asm
            .ccall(rb_obj_is_kind_of as *const u8, vec![rhs, lhs]);

        // Return the result
        self.ctx.stack_pop(2);
        let stack_ret = self.ctx.stack_push(Type::UnknownImm);
        self.asm.mov(stack_ret, ret);

        true
    }

    // Codegen for rb_obj_equal()
    // object identity comparison
    fn jit_rb_obj_equal(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        self.asm.comment("equal?");
        let obj1 = self.ctx.stack_pop(1);
        let obj2 = self.ctx.stack_pop(1);

        self.asm.cmp(obj1, obj2);
        let ret_opnd = self.asm.csel_e(Qtrue.into(), Qfalse.into());

        let stack_ret = self.ctx.stack_push(Type::UnknownImm);
        self.asm.mov(stack_ret, ret_opnd);
        true
    }

    // Codegen for rb_obj_not_equal()
    // object identity comparison
    fn jit_rb_obj_not_equal(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        self.gen_equality_specialized(false) == Some(true)
    }

    // Codegen for rb_int_equal()
    fn jit_rb_int_equal(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        let side_exit = self.get_side_exit(&self.ctx.clone());

        // Check that both operands are fixnums
        self.guard_two_fixnums(side_exit);

        // Compare the arguments
        self.asm.comment("rb_int_equal");
        let arg1 = self.ctx.stack_pop(1);
        let arg0 = self.ctx.stack_pop(1);
        self.asm.cmp(arg0, arg1);
        let ret_opnd = self.asm.csel_e(Qtrue.into(), Qfalse.into());

        let stack_ret = self.ctx.stack_push(Type::UnknownImm);
        self.asm.mov(stack_ret, ret_opnd);
        true
    }

    /// If string is frozen, duplicate it to get a non-frozen string. Otherwise, return it.
    fn jit_rb_str_uplus(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        if argc != 0 {
            return false;
        }

        // We allocate when we dup the string
        self.jit_prepare_routine_call();

        self.asm.comment("Unary plus on string");
        let recv_opnd = self.asm.load(self.ctx.stack_pop(1));
        let flags_opnd = self
            .asm
            .load(Opnd::mem(64, recv_opnd, RUBY_OFFSET_RBASIC_FLAGS));
        self.asm.test(flags_opnd, Opnd::Imm(RUBY_FL_FREEZE as i64));

        let ret_label = self.asm.new_label("stack_ret");

        // String#+@ can only exist on T_STRING
        let stack_ret = self.ctx.stack_push(Type::TString);

        // If the string isn't frozen, we just return it.
        self.asm.mov(stack_ret, recv_opnd);
        self.asm.jz(ret_label);

        // Str is frozen - duplicate it
        let ret_opnd = self.asm.ccall(rb_str_dup as *const u8, vec![recv_opnd]);
        self.asm.mov(stack_ret, ret_opnd);

        self.asm.write_label(ret_label);

        true
    }

    fn jit_rb_str_bytesize(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        self.asm.comment("String#bytesize");

        let recv = self.ctx.stack_pop(1);
        let ret_opnd = self.asm.ccall(rb_str_bytesize as *const u8, vec![recv]);

        let out_opnd = self.ctx.stack_push(Type::Fixnum);
        self.asm.mov(out_opnd, ret_opnd);

        true
    }

    // Codegen for rb_str_to_s()
    // When String#to_s is called on a String instance, the method returns self and
    // most of the overhead comes from setting up the method call. We observed that
    // this situation happens a lot in some workloads.
    fn jit_rb_str_to_s(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        known_recv_class: *const VALUE,
    ) -> bool {
        if !known_recv_class.is_null() && unsafe { *known_recv_class == rb_cString } {
            self.asm.comment("to_s on plain string");
            // The method returns the receiver, which is already on the stack.
            // No stack movement.
            return true;
        }
        false
    }

    // Codegen for rb_str_empty_p()
    fn jit_rb_str_empty_p(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        const _: () = if RUBY_OFFSET_RSTRING_AS_HEAP_LEN != RUBY_OFFSET_RSTRING_EMBED_LEN {
            panic!(
                "same offset to len embedded or not so we can use one code path to read the length"
            );
        };

        let recv_opnd = self.ctx.stack_pop(1);
        let out_opnd = self.ctx.stack_push(Type::UnknownImm);

        self.asm.comment("get string length");
        let str_len_opnd = Opnd::mem(
            std::os::raw::c_long::BITS as u8,
            self.asm.load(recv_opnd),
            RUBY_OFFSET_RSTRING_AS_HEAP_LEN as i32,
        );

        self.asm.cmp(str_len_opnd, Opnd::UImm(0));
        let string_empty = self.asm.csel_e(Qtrue.into(), Qfalse.into());
        self.asm.mov(out_opnd, string_empty);

        true
    }

    // Codegen for rb_str_concat() -- *not* String#concat
    // Frequently strings are concatenated using "out_str << next_str".
    // This is common in Erb and similar templating languages.
    fn jit_rb_str_concat(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        // The << operator can accept integer codepoints for characters
        // as the argument. We only specially optimise string arguments.
        // If the peeked-at compile time argument is something other than
        // a string, assume it won't be a string later either.
        let comptime_arg = self.jit.peek_at_stack(&self.ctx, 0);
        if !unsafe { RB_TYPE_P(comptime_arg, RUBY_T_STRING) } {
            return false;
        }

        // Generate a side exit
        let side_exit = self.get_side_exit(&self.ctx.clone());

        // Guard that the argument is of class String at runtime.
        let arg_type = self.ctx.get_opnd_type(YARVOpnd::StackOpnd(0));

        let concat_arg = self.ctx.stack_pop(1);
        let recv = self.ctx.stack_pop(1);

        // If we're not compile-time certain that this will always be a string, guard at runtime
        if arg_type != Type::CString && arg_type != Type::TString {
            let arg_opnd = self.asm.load(concat_arg);
            if !arg_type.is_heap() {
                self.asm.comment("guard arg not immediate");
                self.asm.test(arg_opnd, (RUBY_IMMEDIATE_MASK as u64).into());
                self.asm.jnz(side_exit);
                self.asm.cmp(arg_opnd, Qfalse.into());
                self.asm.je(side_exit);
            }
            self.guard_object_is_string(arg_opnd, side_exit);
        }

        // Test if string encodings differ. If different, use rb_str_append. If the same,
        // use rb_yjit_str_simple_append, which calls rb_str_cat.
        self.asm.comment("<< on strings");

        // Take receiver's object flags XOR arg's flags. If any
        // string-encoding flags are different between the two,
        // the encodings don't match.
        let recv_reg = self.asm.load(recv);
        let concat_arg_reg = self.asm.load(concat_arg);
        let flags_xor = self.asm.xor(
            Opnd::mem(64, recv_reg, RUBY_OFFSET_RBASIC_FLAGS),
            Opnd::mem(64, concat_arg_reg, RUBY_OFFSET_RBASIC_FLAGS),
        );
        self.asm
            .test(flags_xor, Opnd::UImm(RUBY_ENCODING_MASK as u64));

        // Push once, use the resulting operand in both branches below.
        let stack_ret = self.ctx.stack_push(Type::CString);

        let enc_mismatch = self.asm.new_label("enc_mismatch");
        self.asm.jnz(enc_mismatch);

        // If encodings match, call the simple append function and jump to return
        let ret_opnd = self.asm.ccall(
            rb_yjit_str_simple_append as *const u8,
            vec![recv, concat_arg],
        );
        let ret_label = self.asm.new_label("func_return");
        self.asm.mov(stack_ret, ret_opnd);
        self.asm.jmp(ret_label);

        // If encodings are different, use a slower encoding-aware concatenate
        self.asm.write_label(enc_mismatch);
        let ret_opnd = self
            .asm
            .ccall(rb_str_buf_append as *const u8, vec![recv, concat_arg]);
        self.asm.mov(stack_ret, ret_opnd);
        // Drop through to return

        self.asm.write_label(ret_label);

        true
    }

    // Codegen for rb_ary_empty_p()
    fn jit_rb_ary_empty_p(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        let array_opnd = self.ctx.stack_pop(1);
        let array_reg = self.asm.load(array_opnd);
        let len_opnd = self.get_array_len(array_reg);

        self.asm.test(len_opnd, len_opnd);
        let bool_val = self.asm.csel_z(Qtrue.into(), Qfalse.into());

        let out_opnd = self.ctx.stack_push(Type::UnknownImm);
        self.asm.store(out_opnd, bool_val);

        true
    }

    fn jit_obj_respond_to(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        argc: i32,
        known_recv_class: *const VALUE,
    ) -> bool {
        // respond_to(:sym) or respond_to(:sym, true)
        if argc != 1 && argc != 2 {
            return false;
        }

        if known_recv_class.is_null() {
            return false;
        }

        let recv_class = unsafe { *known_recv_class };

        // Get the method_id from compile time. We will later add a guard against it.
        let mid_sym = self.jit.peek_at_stack(&self.ctx, (argc - 1) as isize);
        if !mid_sym.static_sym_p() {
            return false;
        }
        let mid = unsafe { rb_sym2id(mid_sym) };

        // Option<bool> representing the value of the "include_all" argument and whether it's known
        let allow_priv = if argc == 1 {
            // Default is false
            Some(false)
        } else {
            // Get value from type information (may or may not be known)
            self.ctx
                .get_opnd_type(YARVOpnd::StackOpnd(0))
                .known_truthy()
        };

        let target_cme = unsafe { rb_callable_method_entry_or_negative(recv_class, mid) };

        // Should never be null, as in that case we will be returned a "negative CME"
        assert!(!target_cme.is_null());

        let cme_def_type = unsafe { get_cme_def_type(target_cme) };

        if cme_def_type == VM_METHOD_TYPE_REFINED {
            return false;
        }

        let visibility = if cme_def_type == VM_METHOD_TYPE_UNDEF {
            METHOD_VISI_UNDEF
        } else {
            unsafe { METHOD_ENTRY_VISI(target_cme) }
        };

        let result = match (visibility, allow_priv) {
            (METHOD_VISI_UNDEF, _) => Qfalse, // No method => false
            (METHOD_VISI_PUBLIC, _) => Qtrue, // Public method => true regardless of include_all
            (_, Some(true)) => Qtrue,         // include_all => always true
            (_, _) => return false,           // not public and include_all not known, can't compile
        };

        if result != Qtrue {
            // Only if respond_to_missing? hasn't been overridden
            // In the future, we might want to jit the call to respond_to_missing?
            if !assume_method_basic_definition(self, recv_class, idRespond_to_missing.into()) {
                return false;
            }
        }

        // Invalidate this block if method lookup changes for the method being queried. This works
        // both for the case where a method does or does not exist, as for the latter we asked for a
        // "negative CME" earlier.
        assume_method_lookup_stable(self, target_cme);

        // Generate a side exit
        let side_exit = self.get_side_exit(&self.ctx.clone());

        if argc == 2 {
            // pop include_all argument (we only use its type info)
            self.ctx.stack_pop(1);
        }

        let sym_opnd = self.ctx.stack_pop(1);
        let _recv_opnd = self.ctx.stack_pop(1);

        // This is necessary because we have no guarantee that sym_opnd is a constant
        self.asm.comment("guard known mid");
        self.asm.cmp(sym_opnd, mid_sym.into());
        self.asm.jne(side_exit);

        self.jit_putobject(result);

        true
    }

    fn jit_rb_f_block_given_p(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        self.asm.comment("block_given?");

        // Same as rb_vm_frame_block_handler
        let ep_opnd = self.gen_get_lep();
        let block_handler = self.asm.load(Opnd::mem(
            64,
            ep_opnd,
            SIZEOF_VALUE_I32 * VM_ENV_DATA_INDEX_SPECVAL,
        ));

        self.ctx.stack_pop(1);
        let out_opnd = self.ctx.stack_push(Type::UnknownImm);

        // Return `block_handler != VM_BLOCK_HANDLER_NONE`
        self.asm.cmp(block_handler, VM_BLOCK_HANDLER_NONE.into());
        let block_given = self.asm.csel_ne(Qtrue.into(), Qfalse.into());
        self.asm.mov(out_opnd, block_given);

        true
    }

    fn jit_thread_s_current(
        &mut self,
        _ci: *const rb_callinfo,
        _cme: *const rb_callable_method_entry_t,
        _block: Option<IseqPtr>,
        _argc: i32,
        _known_recv_class: *const VALUE,
    ) -> bool {
        self.asm.comment("Thread.current");
        self.ctx.stack_pop(1);

        // ec->thread_ptr
        let ec_thread_opnd = self.asm.load(Opnd::mem(64, EC, RUBY_OFFSET_EC_THREAD_PTR));

        // thread->self
        let thread_self = Opnd::mem(64, ec_thread_opnd, RUBY_OFFSET_THREAD_SELF);

        let stack_ret = self.ctx.stack_push(Type::UnknownHeap);
        self.asm.mov(stack_ret, thread_self);
        true
    }
}

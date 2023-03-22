use std::{collections::HashMap, mem};

use crate::{
    asm::{CodeBlock, OutlinedCb},
    codegen::{
        gen_code_for_exit_from_stub, gen_full_cfunc_return, gen_leave_exit, CodeGenerator, CodePtr,
        CodepagePatch,
    },
    core::gen_branch_stub_hit_trampoline,
    cruby::{
        get_def_method_serial, rb_callable_method_entry_t, rb_callinfo, rb_intern,
        rb_method_entry_at, IseqPtr, VALUE,
    },
    dev::options::get_option,
};

// Return true when the codegen function generates code.
// known_recv_klass is non-NULL when the caller has used jit_guard_known_klass().
// See yjit_reg_method().
pub type MethodGenFn = fn(
    code_generator: &mut CodeGenerator,
    ci: *const rb_callinfo,
    cme: *const rb_callable_method_entry_t,
    block: Option<IseqPtr>,
    argc: i32,
    known_recv_class: *const VALUE,
) -> bool;

/// Global state needed for code generation
pub struct CodegenGlobals {
    /// Inline code block (fast path)
    inline_cb: CodeBlock,

    /// Outlined code block (slow path)
    outlined_cb: Option<OutlinedCb>,

    /// Code for exiting back to the interpreter from the leave instruction
    leave_exit_code: CodePtr,

    // For exiting from YJIT frame from branch_stub_hit().
    // Filled by gen_code_for_exit_from_stub().
    stub_exit_code: CodePtr,

    // For servicing branch stubs
    branch_stub_hit_trampoline: CodePtr,

    // Code for full logic of returning from C method and exiting to the interpreter
    outline_full_cfunc_return_pos: CodePtr,

    /// For implementing global code invalidation
    global_inval_patches: Vec<CodepagePatch>,

    // Methods for generating code for hardcoded (usually C) methods
    method_codegen_table: HashMap<usize, MethodGenFn>,

    /// Page indexes for outlined code that are not associated to any ISEQ.
    ocb_pages: Vec<usize>,

    /// How many times code GC has been executed.
    code_gc_count: usize,
}

/// Private singleton instance of the codegen globals
static mut CODEGEN_GLOBALS: Option<CodegenGlobals> = None;

impl CodegenGlobals {
    /// Initialize the codegen globals
    pub fn init() {
        // Executable memory and code page size in bytes
        let mem_size = get_option!(exec_mem_size);

        #[cfg(not(test))]
        let (mut cb, mut ocb) = {
            use crate::cruby::{rb_yjit_get_page_size, rb_yjit_reserve_addr_space};
            use crate::utils::IntoUsize;
            use std::cell::RefCell;
            use std::rc::Rc;

            let virt_block: *mut u8 = unsafe { rb_yjit_reserve_addr_space(mem_size as u32) };

            // Memory protection syscalls need page-aligned addresses, so check it here. Assuming
            // `virt_block` is page-aligned, `second_half` should be page-aligned as long as the
            // page size in bytes is a power of two 2¹⁹ or smaller. This is because the user
            // requested size is half of mem_option × 2²⁰ as it's in MiB.
            //
            // Basically, we don't support x86-64 2MiB and 1GiB pages. ARMv8 can do up to 64KiB
            // (2¹⁶ bytes) pages, which should be fine. 4KiB pages seem to be the most popular though.
            let page_size = unsafe { rb_yjit_get_page_size() };
            assert_eq!(
                virt_block as usize % page_size.into_usize(),
                0,
                "Start of virtual address block should be page-aligned",
            );

            use crate::virtualmem::{SystemAllocator, VirtualMem};

            use std::ptr::NonNull;

            let mem_block = VirtualMem::new(
                SystemAllocator {},
                page_size,
                NonNull::new(virt_block).unwrap(),
                mem_size,
            );
            let mem_block = Rc::new(RefCell::new(mem_block));

            let freed_pages = Rc::new(None);
            let cb = CodeBlock::new(mem_block.clone(), false, freed_pages.clone());
            let ocb = OutlinedCb::wrap(CodeBlock::new(mem_block, true, freed_pages));

            (cb, ocb)
        };

        // In test mode we're not linking with the C code
        // so we don't allocate executable memory
        #[cfg(test)]
        let mut cb = CodeBlock::new_dummy(mem_size / 2);
        #[cfg(test)]
        let mut ocb = OutlinedCb::wrap(CodeBlock::new_dummy(mem_size / 2));

        let ocb_start_addr = ocb.unwrap().get_write_ptr();
        let leave_exit_code = gen_leave_exit(&mut ocb);

        let stub_exit_code = gen_code_for_exit_from_stub(&mut ocb);

        let branch_stub_hit_trampoline = gen_branch_stub_hit_trampoline(&mut ocb);

        // Generate full exit code for C func
        let cfunc_exit_code = gen_full_cfunc_return(&mut ocb);

        let ocb_end_addr = ocb.unwrap().get_write_ptr();
        let ocb_pages = ocb.unwrap().addrs_to_pages(ocb_start_addr, ocb_end_addr);

        // Mark all code memory as executable
        cb.mark_all_executable();
        ocb.unwrap().mark_all_executable();

        let mut codegen_globals = CodegenGlobals {
            inline_cb: cb,
            outlined_cb: Some(ocb),
            leave_exit_code,
            stub_exit_code,
            outline_full_cfunc_return_pos: cfunc_exit_code,
            branch_stub_hit_trampoline,
            global_inval_patches: Vec::new(),
            method_codegen_table: HashMap::new(),
            ocb_pages,
            code_gc_count: 0,
        };

        // Register the method codegen functions
        CodeGenerator::init_overrides(&mut codegen_globals);

        // Initialize the codegen globals instance
        unsafe {
            CODEGEN_GLOBALS = Some(codegen_globals);
        }
    }

    // Register a specialized codegen function for a particular method. Note that
    // the if the function returns true, the code it generates runs without a
    // control frame and without interrupt checks. To avoid creating observable
    // behavior changes, the codegen function should only target simple code paths
    // that do not allocate and do not make method calls.
    pub fn yjit_reg_method(&mut self, klass: VALUE, mid_str: &str, gen_fn: MethodGenFn) {
        let id_string = std::ffi::CString::new(mid_str).expect("couldn't convert to CString!");
        let mid = unsafe { rb_intern(id_string.as_ptr()) };
        let me = unsafe { rb_method_entry_at(klass, mid) };

        if me.is_null() {
            panic!("undefined optimized method!");
        }

        // For now, only cfuncs are supported
        //RUBY_ASSERT(me && me->def);
        //RUBY_ASSERT(me->def->type == VM_METHOD_TYPE_CFUNC);

        let method_serial = unsafe {
            let def = (*me).def;
            get_def_method_serial(def)
        };

        self.method_codegen_table.insert(method_serial, gen_fn);
    }

    /// Get a mutable reference to the codegen globals instance
    pub fn get_instance() -> &'static mut CodegenGlobals {
        unsafe { CODEGEN_GLOBALS.as_mut().unwrap() }
    }

    pub fn has_instance() -> bool {
        unsafe { CODEGEN_GLOBALS.as_mut().is_some() }
    }

    /// Get a mutable reference to the inline code block
    pub fn get_inline_cb() -> &'static mut CodeBlock {
        &mut CodegenGlobals::get_instance().inline_cb
    }

    pub fn set_outlined_cb(value: OutlinedCb) {
        CodegenGlobals::get_instance().outlined_cb = Some(value);
    }

    pub fn take_outlined_cb() -> Option<OutlinedCb> {
        CodegenGlobals::get_instance().outlined_cb.take()
    }

    pub fn with_outlined_cb<F: FnOnce(&mut OutlinedCb)>(f: F) {
        let globals = CodegenGlobals::get_instance();
        if let Some(outlined_cb) = &mut globals.outlined_cb {
            f(outlined_cb);
        } else {
            panic!("No outlined code block available in with");
        }
    }

    pub fn map_outlined_cb<F: FnOnce(&mut OutlinedCb) -> T, T>(f: F) -> Option<T> {
        let globals = CodegenGlobals::get_instance();
        if let Some(outlined_cb) = &mut globals.outlined_cb {
            Some(f(outlined_cb))
        } else {
            panic!("No outlined code block available in map");
        }
    }

    pub fn get_leave_exit_code() -> CodePtr {
        CodegenGlobals::get_instance().leave_exit_code
    }

    pub fn get_stub_exit_code() -> CodePtr {
        CodegenGlobals::get_instance().stub_exit_code
    }

    pub fn push_global_inval_patch(i_pos: CodePtr, o_pos: CodePtr) {
        let patch = CodepagePatch {
            inline_patch_pos: i_pos,
            outlined_target_pos: o_pos,
        };
        CodegenGlobals::get_instance()
            .global_inval_patches
            .push(patch);
    }

    // Drain the list of patches and return it
    pub fn take_global_inval_patches() -> Vec<CodepagePatch> {
        let globals = CodegenGlobals::get_instance();
        mem::take(&mut globals.global_inval_patches)
    }

    pub fn get_outline_full_cfunc_return_pos() -> CodePtr {
        CodegenGlobals::get_instance().outline_full_cfunc_return_pos
    }

    pub fn get_branch_stub_hit_trampoline() -> CodePtr {
        CodegenGlobals::get_instance().branch_stub_hit_trampoline
    }

    pub fn look_up_codegen_method(method_serial: usize) -> Option<MethodGenFn> {
        let table = &CodegenGlobals::get_instance().method_codegen_table;

        let option_ref = table.get(&method_serial);
        option_ref.copied()
    }

    pub fn get_ocb_pages() -> &'static Vec<usize> {
        &CodegenGlobals::get_instance().ocb_pages
    }

    pub fn incr_code_gc_count() {
        CodegenGlobals::get_instance().code_gc_count += 1;
    }

    pub fn get_code_gc_count() -> usize {
        CodegenGlobals::get_instance().code_gc_count
    }
}

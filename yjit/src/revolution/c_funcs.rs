use std::{os::raw, ffi::c_void};

use crate::{cruby::{IseqPtr, EcPtr, VALUE}, utils::c_callable};

use super::global::get_compiler;
use super::traits::Compiler;



/// Called from C code to begin compiling a function
/// NOTE: this should be wrapped in RB_VM_LOCK_ENTER(), rb_vm_barrier() on the C side
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_gen_entry_point(iseq: IseqPtr, ec: EcPtr) -> *const u8 {
    get_compiler().entry_point(iseq, ec)
}

c_callable! {
    /// Generated code calls this function with the SysV calling convention.
    /// See [set_branch_target].
    pub fn branch_stub_hit(
        branch_ptr: *const c_void,
        target_idx: u32,
        ec: EcPtr,
    ) -> *const u8 {
        get_compiler().stub_hit(branch_ptr, target_idx, ec)
    }
}

/// Parse one command-line option.
/// This is called from ruby.c
#[no_mangle]
pub extern "C" fn rb_yjit_parse_option(str_ptr: *const raw::c_char) -> bool {
    get_compiler().parse_options(str_ptr)
}

/// Is YJIT on? The interpreter uses this function to decide whether to increment
/// ISEQ call counters. See jit_exec().
/// This is used frequently since it's used on every method call in the interpreter.
#[no_mangle]
pub extern "C" fn rb_yjit_enabled_p() -> bool {
    get_compiler().enabled()
}

/// After how many calls YJIT starts compiling a method
#[no_mangle]
pub extern "C" fn rb_yjit_call_threshold() -> raw::c_uint {
    get_compiler().call_threshold()
}

/// This function is called from C code
#[no_mangle]
pub extern "C" fn rb_yjit_init_rust() {
    get_compiler().init();
}

/// Free and recompile all existing JIT code
#[no_mangle]
pub extern "C" fn rb_yjit_code_gc(ec: EcPtr, ruby_self: VALUE) -> VALUE {
    get_compiler().code_gc(ec, ruby_self)
}

/// Simulate a situation where we are out of executable memory
#[no_mangle]
pub extern "C" fn rb_yjit_simulate_oom_bang(ec: EcPtr, ruby_self: VALUE) -> VALUE {
    get_compiler().simulate_out_of_memory(ec, ruby_self)
}

/// Free the per-iseq payload
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_free(payload: *mut c_void) {
    get_compiler().free(payload)
}

/// GC callback for marking GC objects in the the per-iseq payload.
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_mark(payload: *mut c_void) {
    get_compiler().mark(payload)
}

/// GC callback for updating GC objects in the the per-iseq payload.
/// This is a mirror of [rb_yjit_iseq_mark].
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_update_references(payload: *mut c_void) {
    get_compiler().update_references(payload)
}

use crate::{
    asm::CodeBlock,
    codegen::globals::CodegenGlobals,
    core::{free_block, gen_entry_point},
    cruby::{
        get_iseq_encoded_size, rb_bug, rb_gc_location, rb_gc_mark_movable,
        rb_get_iseq_body_stack_max, rb_vm_barrier, EcPtr, IseqPtr, Qnil, VALUE,
    },
    dev::options::{get_option, parse_option},
    dev::stats::{incr_counter, YjitExitLocations},
    meta::{block::IseqPayload, invariants::Invariants},
    utils::IntoUsize,
};

use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    mem,
    os::raw::{self, c_void},
};

/// For tracking whether the user enabled YJIT through command line arguments or environment
/// variables. AtomicBool to avoid `unsafe`. On x86 it compiles to simple movs.
/// See <https://doc.rust-lang.org/std/sync/atomic/enum.Ordering.html>
/// See [rb_yjit_enabled_p]
static YJIT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Parse one command-line option.
/// This is called from ruby.c
#[no_mangle]
pub extern "C" fn rb_yjit_parse_option(str_ptr: *const raw::c_char) -> bool {
    parse_option(str_ptr).is_some()
}

/// Is YJIT on? The interpreter uses this function to decide whether to increment
/// ISEQ call counters. See jit_exec().
/// This is used frequently since it's used on every method call in the interpreter.
#[no_mangle]
pub extern "C" fn rb_yjit_enabled_p() -> raw::c_int {
    // Note that we might want to call this function from signal handlers so
    // might need to ensure signal-safety(7).
    YJIT_ENABLED.load(Ordering::Acquire).into()
}

/// Like rb_yjit_enabled_p, but for Rust code.
pub fn yjit_enabled_p() -> bool {
    YJIT_ENABLED.load(Ordering::Acquire)
}

/// After how many calls YJIT starts compiling a method
#[no_mangle]
pub extern "C" fn rb_yjit_call_threshold() -> raw::c_uint {
    get_option!(call_threshold) as raw::c_uint
}

/// This function is called from C code
#[no_mangle]
pub extern "C" fn rb_yjit_init_rust() {
    // TODO: need to make sure that command-line options have been
    // initialized by CRuby

    // Catch panics to avoid UB for unwinding into C frames.
    // See https://doc.rust-lang.org/nomicon/exception-safety.html
    let result = std::panic::catch_unwind(|| {
        Invariants::init();
        CodegenGlobals::init();
        YjitExitLocations::init();

        rb_bug_panic_hook();

        // YJIT enabled and initialized successfully
        YJIT_ENABLED.store(true, Ordering::Release);
    });

    if result.is_err() {
        println!("YJIT: rb_yjit_init_rust() panicked. Aborting.");
        std::process::abort();
    }
}

/// At the moment, we abort in all cases we panic.
/// To aid with getting diagnostics in the wild without requiring
/// people to set RUST_BACKTRACE=1, register a panic hook that crash using rb_bug().
/// rb_bug() might not be as good at printing a call trace as Rust's stdlib, but
/// it dumps some other info that might be relevant.
///
/// In case we want to start doing fancier exception handling with panic=unwind,
/// we can revisit this later. For now, this helps to get us good bug reports.
fn rb_bug_panic_hook() {
    use std::io::{stderr, Write};
    use std::panic;

    // Probably the default hook. We do this very early during process boot.
    let previous_hook = panic::take_hook();

    panic::set_hook(Box::new(move |panic_info| {
        // Not using `eprintln` to avoid double panic.
        let _ = stderr().write_all(b"ruby: YJIT has panicked. More info to follow...\n");

        previous_hook(panic_info);

        unsafe {
            rb_bug(b"YJIT panicked\0".as_ref().as_ptr() as *const raw::c_char);
        }
    }));
}

/// Called from C code to begin compiling a function
/// NOTE: this should be wrapped in RB_VM_LOCK_ENTER(), rb_vm_barrier() on the C side
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_gen_entry_point(iseq: IseqPtr, ec: EcPtr) -> *const u8 {
    // Reject ISEQs with very large temp stacks,
    // this will allow us to use u8/i8 values to track stack_size and sp_offset
    let stack_max = unsafe { rb_get_iseq_body_stack_max(iseq) };
    if stack_max >= i8::MAX as u32 {
        incr_counter!(iseq_stack_too_large);
        return std::ptr::null();
    }

    // Reject ISEQs that are too long,
    // this will allow us to use u16 for instruction indices if we want to,
    // very long ISEQs are also much more likely to be initialization code
    let iseq_size = unsafe { get_iseq_encoded_size(iseq) };
    if iseq_size >= u16::MAX as u32 {
        incr_counter!(iseq_too_long);
        return std::ptr::null();
    }

    let maybe_code_ptr = gen_entry_point(iseq, ec);

    match maybe_code_ptr {
        Some(ptr) => ptr.raw_ptr(),
        None => std::ptr::null(),
    }
}

/// Free and recompile all existing JIT code
#[no_mangle]
pub extern "C" fn rb_yjit_code_gc(_ec: EcPtr, _ruby_self: VALUE) -> VALUE {
    if !yjit_enabled_p() {
        return Qnil;
    }

    let cb = CodegenGlobals::get_inline_cb();
    cb.code_gc();
    Qnil
}

/// Simulate a situation where we are out of executable memory
#[no_mangle]
pub extern "C" fn rb_yjit_simulate_oom_bang(_ec: EcPtr, _ruby_self: VALUE) -> VALUE {
    // If YJIT is not enabled, do nothing
    if !yjit_enabled_p() {
        return Qnil;
    }

    // Enabled in debug mode only for security
    if cfg!(debug_assertions) {
        let cb = CodegenGlobals::get_inline_cb();
        cb.set_pos(cb.get_mem_size());
        CodegenGlobals::with_outlined_cb(|ocb| {
            let ocb = ocb.unwrap();
            ocb.set_pos(ocb.get_mem_size())
        });
    }

    Qnil
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

    CodegenGlobals::with_outlined_cb(|ocb| {
        ocb.unwrap().mark_all_executable();
    });
}

use std::{ffi::c_void, os::raw};

use crate::cruby::{EcPtr, IseqPtr, VALUE};

// Do I want to use raw here? Probably not.

// Looks like I'm missing some functions from Ivariants.
// Need to add these to get the true interface.

pub trait Compiler {
    fn init(&mut self);
    fn entry_point(&mut self, iseq: IseqPtr, ec: EcPtr) -> *const u8;
    fn stub_hit(&mut self, branch_ptr: *const c_void, target_idx: u32, ec: EcPtr) -> *const u8;
    fn parse_options(&mut self, str_ptr: *const raw::c_char) -> bool;
    fn enabled(&mut self) -> bool;
    fn call_threshold(&mut self) -> raw::c_uint;
    fn code_gc(&mut self, ec: EcPtr, ruby_self: VALUE) -> VALUE;
    fn simulate_out_of_memory(&mut self, ec: EcPtr, ruby_self: VALUE) -> VALUE;
    fn free(&mut self, payload: *mut c_void);
    fn mark(&mut self, payload: *mut c_void);
    fn update_references(&mut self, payload: *mut c_void);
}

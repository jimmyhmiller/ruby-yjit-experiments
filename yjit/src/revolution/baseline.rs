use std::os::raw;

use crate::{
    codegen::{generator::CodeGenerator, globals::CodegenContext},
    meta::invariants::Invariants,
};

use super::traits::Compiler;

#[allow(unused)]
pub struct Baseline {
    codegen_context: CodegenContext,
    generator: CodeGenerator,
    invariants: Invariants,
}

#[allow(unused)]
impl Baseline {
    pub fn new() -> Self {
        unimplemented!();
    }
}

#[allow(unused)]
impl Compiler for Baseline {
    fn init(&mut self) {
        todo!()
    }

    fn entry_point(&mut self, iseq: crate::cruby::IseqPtr, ec: crate::cruby::EcPtr) -> *const u8 {
        todo!()
    }

    fn stub_hit(
        &mut self,
        branch_ptr: *const std::ffi::c_void,
        target_idx: u32,
        ec: crate::cruby::EcPtr,
    ) -> *const u8 {
        todo!()
    }

    fn parse_options(&mut self, str_ptr: *const raw::c_char) -> bool {
        todo!()
    }

    fn enabled(&mut self) -> bool {
        todo!()
    }

    fn call_threshold(&mut self) -> raw::c_uint {
        todo!()
    }

    fn code_gc(
        &mut self,
        ec: crate::cruby::EcPtr,
        ruby_self: crate::cruby::VALUE,
    ) -> crate::cruby::VALUE {
        todo!()
    }

    fn simulate_out_of_memory(
        &mut self,
        ec: crate::cruby::EcPtr,
        ruby_self: crate::cruby::VALUE,
    ) -> crate::cruby::VALUE {
        todo!()
    }

    fn free(&mut self, payload: *mut std::ffi::c_void) {
        todo!()
    }

    fn mark(&mut self, payload: *mut std::ffi::c_void) {
        todo!()
    }

    fn update_references(&mut self, payload: *mut std::ffi::c_void) {
        todo!()
    }
}

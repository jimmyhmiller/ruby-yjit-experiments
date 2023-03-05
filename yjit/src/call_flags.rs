use std::{
    ops::{BitAnd, BitOr, BitOrAssign},
    os::raw::c_uint,
};

use crate::{
    backend::ir::Opnd,
    cruby::{
        rb_callinfo, vm_ci_flag, VM_CALL_ARGS_BLOCKARG, VM_CALL_ARGS_SPLAT, VM_CALL_FCALL,
        VM_CALL_KWARG, VM_CALL_KW_SPLAT, VM_CALL_OPT_SEND, VM_CALL_ZSUPER,
    },
};

pub struct CallFlags(c_uint);

impl CallFlags {
    pub fn from_ci(ci: *const rb_callinfo) -> Self {
        Self(unsafe { vm_ci_flag(ci) })
    }

    pub fn is_kw_splat(&self) -> bool {
        self.0 & VM_CALL_KW_SPLAT != 0
    }

    pub fn is_block_arg(&self) -> bool {
        self.0 & VM_CALL_ARGS_BLOCKARG != 0
    }

    pub fn is_kw_arg(&self) -> bool {
        self.0 & VM_CALL_KWARG != 0
    }

    pub fn is_splat(&self) -> bool {
        self.0 & VM_CALL_ARGS_SPLAT != 0
    }

    pub fn is_fcall(&self) -> bool {
        self.0 & VM_CALL_FCALL != 0
    }

    pub fn is_opt_send(&self) -> bool {
        self.0 & VM_CALL_OPT_SEND != 0
    }

    pub fn is_zsuper(&self) -> bool {
        self.0 & VM_CALL_ZSUPER != 0
    }
}

impl BitOr for CallFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitAnd for CallFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAnd<u32> for CallFlags {
    type Output = Self;

    fn bitand(self, rhs: u32) -> Self {
        Self(self.0 & rhs)
    }
}

impl BitOrAssign<u32> for CallFlags {
    fn bitor_assign(&mut self, rhs: u32) {
        self.0 |= rhs;
    }
}
impl BitOrAssign for CallFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl From<CallFlags> for u32 {
    fn from(val: CallFlags) -> Self {
        val.0
    }
}

impl From<CallFlags> for Opnd {
    fn from(val: CallFlags) -> Self {
        Opnd::UImm(val.0 as u64)
    }
}

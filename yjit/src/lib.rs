#![allow(clippy::too_many_arguments)] // temporary so I can fix others
mod asm;
mod backend;
mod call_flags;
mod codegen;
mod core;
mod cruby;
mod disasm;
mod invariants;
mod jit_state;
mod options;
mod stats;
mod utils;
mod virtualmem;
mod yjit;

use std::mem::MaybeUninit;
use std::sync::{Mutex, MutexGuard, Once};

use crate::cruby::{with_vm_lock, src_loc};

use super::old_world::OldWorld;

pub type CompilerInstance = OldWorld;

// I could make this dynamic. But probably no good use for that right now.
// I can imagine a Compiler implementation that abstracts over multiple though

fn ensure_compiler_setup() -> &'static Mutex<CompilerInstance> {
    static mut COMPILER: MaybeUninit<Mutex<CompilerInstance>> = MaybeUninit::uninit();
    static COMPILER_ONCE: Once = Once::new();

    // Safety: initializing the variable is only done once, and reading is
    // possible only after initialization.
    unsafe {
        COMPILER_ONCE.call_once(|| {
            let compiler = CompilerInstance::new();
            COMPILER.write(Mutex::new(compiler));
        });
        // We've initialized it at this point, so it's safe to return the reference.
        COMPILER.assume_init_ref()
    }
}

static mut REASON : String = String::new();

pub fn get_compiler<'a>(reason: &str) -> MutexGuard<'a, CompilerInstance> {
    
    let compiler = ensure_compiler_setup().try_lock();
    match compiler {
        Ok(compiler) => {
            unsafe { REASON = reason.to_string() };
            return compiler;
        }
        Err(_) => {
            panic!("Tried to lock for {} but already locked for {}", reason, unsafe { REASON.clone() })
        }
    }
}

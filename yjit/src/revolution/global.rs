use std::mem::MaybeUninit;
use std::sync::{Mutex, MutexGuard, Once};

use super::old_world::OldWorld;

type CompilerInstance = OldWorld;

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

pub fn get_compiler<'a>() -> MutexGuard<'a, CompilerInstance> {
    ensure_compiler_setup().lock().unwrap()
}

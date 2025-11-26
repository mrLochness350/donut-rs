/// Trait that unifies loader behavior.
pub trait ShellcodeLoader {
    /// Start the loader's loading process.
    fn load(&mut self) -> crate::errors::DonutResult<()>;
}

/// Azathoth global allocator (enabled with `loader` feature).
#[cfg(feature = "loader")]
#[unsafe(link_section = ".text")]
#[global_allocator]
pub static GLOBAL_ALLOCATOR: azathoth_allocator::allocator::AzathothAllocator =
    azathoth_allocator::allocator::AzathothAllocator::new();


/// Small helper to reduce `Option` unwrapping noise (Windows only).
#[cfg(target_os = "windows")]
#[unsafe(link_section = ".text")]
pub fn resolve<T>(opt: Option<T>) -> crate::prelude::DonutResult<T> {
    opt.ok_or_else(|| crate::prelude::DonutError::ApiResolutionFailure)
}

/// Trap and never return (debug helper).
#[doc(hidden)]
#[unsafe(link_section = ".text")]
pub fn tnoret() -> ! {
    unsafe { core::arch::asm!("int3", options(noreturn)) }
}

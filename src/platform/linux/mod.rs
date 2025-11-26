//! Linux-specific platform support module.
//!
//! This module provides **type definitions, constants, utility functions, and syscall wrappers**
//! used by the Linux implementation of this crate. It exposes safe and unsafe bindings to
//! Linux system calls, libc functions (if enabled), and dynamic library operations such as
//! `dlopen` and `dlsym`.
//!
//! # Overview
//!
//! - [`fn_defs`] - Function type definitions used throughout the Linux platform layer.
//! - [`types`] - Linux-exclusive data types and structures.
//! - [`consts`] - System call numbers, flags, and constants for Linux syscalls.
//! - [`utils`] - Utility helpers for low-level Linux operations.
//! - [`syscall`] - Raw syscall wrappers (`syscall1` through `syscall6`) for direct kernel access.
//! - [`loader_unix`] - Loader bytes
//!
//! # Conditional Features
//!
//! - With the `libc` feature enabled, certain functions are re-exported directly from `libc`
//!   (e.g., `dlopen`, `dlsym`, `mmap`, `memcpy`, etc.).
//! - Without `libc`, equivalent extern definitions are provided and syscalls are used directly.
//!
//! # Example
//! ```no_run
//! use base::{
//!     platform::linux::syscall::syscall3,
//!     platform::linux::consts::{SYS_WRITE}
//! };
//!
//! // Write "Hello\n" to stdout using a raw syscall
//! let buf = b"Hello\n";
//! unsafe {
//!     let result = syscall3(SYS_WRITE, 1, buf.as_ptr() as usize, buf.len());
//!     assert!(result > 0);
//! }
//! ```
//!
//! # Safety
//! Many functions in this module are marked `unsafe` because they expose raw Linux syscalls
//! or FFI bindings. The caller must ensure:
//!
//! - Pointers are valid and correctly aligned.
//! - Arguments comply with the target syscall’s expectations.
//! - Error codes are properly handled (negative return values).
//!
//! Misuse of these functions can lead to undefined behavior, segmentation faults, or data corruption.

/// Function type definitions used by Linux syscalls and FFI operations.
pub mod fn_defs; // Fully documented

/// Linux-exclusive types (structs, enums, and low-level primitives).
pub mod types; // Fully documented

// #[cfg(feature = "std")]
/// Linux constants including syscall numbers, flags, and error codes.
pub mod consts; // Fully documented

/// Linux internal logging module (crate-private).
pub(crate) mod logging; // Fully documented

/// Utility functions for Linux-specific low-level operations.
pub mod utils;

#[cfg(feature = "std")]
/// Loader byte array for the linux loader
pub mod loader_unix;
//
// #[cfg(target_os = "linux")]
// #[cfg(feature = "libc")]
// pub use libc::{dlsym, dlopen, memcpy, memmove, mmap, memset, mprotect, munmap};

#[cfg(target_os = "linux")]
#[cfg(not(feature = "libc"))]
unsafe extern "C" {
    /// Looks up a symbol in a dynamically loaded library.
    ///
    /// Equivalent to `dlsym(3)` from libc.
    ///
    /// # Safety
    /// - `handle` must be a valid handle from `dlopen`.
    /// - `name` must point to a null-terminated C string.
    pub fn dlsym(handle: *mut core::ffi::c_void, name: *const u8) -> *mut core::ffi::c_void;

    /// Opens a dynamic library and returns a handle to it.
    ///
    /// Equivalent to `dlopen(3)` from libc.
    ///
    /// # Safety
    /// - `name` must point to a null-terminated C string representing the library path or name.
    /// - `flags` must be valid flags recognized by `dlopen`.
    pub fn dlopen(name: *const u8, flags: i32) -> *mut core::ffi::c_void;
}


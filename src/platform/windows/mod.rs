//! Windows-specific platform module.
//!
//! This module provides low-level Windows API bindings, constants,
//! types, and helper utilities required for Windows builds.
//!
//! # Overview
//!
//! - [`fn_defs`](fn_defs) - Definitions for Windows API function pointers and calling conventions.
//!


/// Definitions for Windows API function pointers and signatures.
#[cfg(all(feature = "loader", target_os = "windows"))]
pub mod fn_defs;
/// Struct to fix borrow issue with the windows stub network code
#[cfg(all(feature = "loader", target_os = "windows"))]
pub mod url_context;

#[cfg(feature = "std")]
/// Windows loader byte array
pub mod loader_win;
/// Windows consts
pub mod consts;
/// Simple helper to resolve API calls
///
/// # Safety
///
/// This function calls `get_proc_address` and `transmute_copy` which are unsafe and interact with low level objects
#[cfg(all(feature = "loader", target_os = "windows"))]
#[unsafe(link_section = ".text")]
pub unsafe fn resolve_api<T>(handle: *mut u8, hash: u32, seed: u32) -> T {
    unsafe {
        let addr = match azathoth_libload::get_proc_address(handle, &(crate::utils::globals::donut_hasher, seed), hash) {
            Some(addr) => addr,
            None => {
                crate::prelude::tnoret();
            }
        };
        core::mem::transmute_copy::<_, T>(&addr)
    }
}



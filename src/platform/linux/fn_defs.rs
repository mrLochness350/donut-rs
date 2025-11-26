#![allow(non_snake_case, unused, non_camel_case_types)]

use core::ffi::{c_char, c_void};
use azathoth_core::os::linux::fn_defs::{CurlEasyCleanup_t, CurlEasyInit_t, CurlEasyPerform_t, CurlEasySetOptFn_t, CurlEasySetOptPtr_t, CurlEasySetOptStr_t, CurlEasySetOpt_t, CurlGlobalCleanup_t, CurlGlobalInit_t, ErrnoLocation_t, Execve_t, Fork_t, MemFdCreate_t, Write_t};

/// Container for Linux-specific dynamically resolved APIs.
///
/// Holds grouped function pointers for cURL and (optionally) zlib
/// functions that are dynamically loaded at runtime via `dlsym`.
#[derive(Clone, Debug, Default)]
pub struct UnixApi {
    /// Collection of cURL-related function pointers.
    pub curl_apis: CurlApis,
}

/// Utility API set containing basic Linux syscalls loaded dynamically.
///
/// This struct stores function pointers to memory/file descriptors, process
/// control, and I/O-related system calls typically obtained from `libc`.
#[derive(Clone, Debug, Default)]
pub struct UtilApis {
    /// `memfd_create` syscall to create anonymous memory-backed files.
    pub memfd_create: Option<MemFdCreate_t>,
    /// `fork` syscall to create a child process.
    pub fork: Option<Fork_t>,
    /// `execve` syscall to replace process image.
    pub execve: Option<Execve_t>,
    /// Retrieves the current `errno` location.
    pub errno_location: Option<ErrnoLocation_t>,
    /// Low-level `write` syscall for file descriptors.
    pub write: Option<Write_t>,
}

/// Dynamically resolved cURL function pointers.
///
/// These functions are loaded from the system's cURL library
/// and allow HTTP request execution without static linking.
#[derive(Clone, Debug, Default)]
pub struct CurlApis {
    /// Initializes a new easy handle.
    pub curl_easy_init: Option<CurlEasyInit_t>,
    /// Initializes global cURL state.
    pub curl_global_init: Option<CurlGlobalInit_t>,
    /// Generic `curl_easy_setopt` with variadic parameters.
    pub curl_easy_set_opt: Option<CurlEasySetOpt_t>,
    /// Executes an HTTP request using the easy handle.
    pub curl_easy_perform: Option<CurlEasyPerform_t>,
    /// Cleans up and frees an easy handle.
    pub curl_easy_cleanup: Option<CurlEasyCleanup_t>,
    /// Sets an option with a string value.
    pub curl_easy_set_opt_str: Option<CurlEasySetOptStr_t>,
    /// Sets an option with a callback function.
    pub curl_easy_set_opt_fn: Option<CurlEasySetOptFn_t>,
    /// Sets an option with a raw pointer value.
    pub curl_easy_set_opt_ptr: Option<CurlEasySetOptPtr_t>,
    /// Cleans up global cURL state.
    pub curl_global_cleanup: Option<CurlGlobalCleanup_t>,
}

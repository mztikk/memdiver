//! Low-level operating-system bindings used by [`memdiver-core`].
//!
//! This crate is the only place in the workspace that contains platform
//! specific code and `unsafe` blocks. It exposes a deliberately small,
//! handle-based API:
//!
//! * [`ProcessHandle`] pins one process and its memory for its entire lifetime.
//! * Reads and writes report how many bytes the operating system transferred;
//!   deciding whether a short transfer is an error is the caller's job.
//! * Errors are reported as [`Error`] values carrying an [`ErrorKind`] and the
//!   raw operating-system error code. No platform error is flattened into a
//!   string without keeping the code around.
//!
//! Most users should depend on the [`memdiver`] façade or [`memdiver-core`]
//! instead of using this crate directly. The API is public so that the safe
//! layer can be audited independently, but it is not designed for convenient
//! end-user consumption.
//!
//! # Supported targets
//!
//! Linux and Windows are supported. Other targets fail to compile with an
//! explicit error instead of silently pretending memory access is available.
//!
//! [`memdiver`]: https://github.com/mztikk/memdiver/tree/main/crates/memdiver
//! [`memdiver-core`]: https://github.com/mztikk/memdiver/tree/main/crates/memdiver-core

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::path::PathBuf;

use bitflags::bitflags;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{ProcessHandle, enable_debug_privilege, processes};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{ProcessHandle, enable_debug_privilege, processes};

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("memdiver supports only Linux and Windows targets");

bitflags! {
    /// Access protection of a memory region.
    ///
    /// The flags model the semantic access rights of a page or mapping rather
    /// than a raw operating-system bitmask. On Windows, copy-on-write pages
    /// report [`Protection::WRITE`] because writes are permitted (the OS then
    /// makes a private copy). On Linux, a write-only mapping reports only
    /// [`Protection::WRITE`], while Windows cannot represent write-only pages.
    ///
    /// [`Protection::GUARD`] is only reported by Windows (`PAGE_GUARD`); Linux
    /// never sets it.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct Protection: u8 {
        /// The region can be read.
        const READ = 0b0001;
        /// The region can be written.
        const WRITE = 0b0010;
        /// The region can be executed.
        const EXECUTE = 0b0100;
        /// The region is a Windows guard page.
        const GUARD = 0b1000;
    }
}

impl Protection {
    /// Returns `true` when the region can be read.
    #[must_use]
    pub fn is_readable(self) -> bool {
        self.contains(Self::READ)
    }

    /// Returns `true` when the region can be written.
    #[must_use]
    pub fn is_writable(self) -> bool {
        self.contains(Self::WRITE)
    }

    /// Returns `true` when the region can be executed.
    #[must_use]
    pub fn is_executable(self) -> bool {
        self.contains(Self::EXECUTE)
    }

    /// Returns `true` when the region is a guard page.
    #[must_use]
    pub fn is_guarded(self) -> bool {
        self.contains(Self::GUARD)
    }
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let read = if self.is_readable() { 'r' } else { '-' };
        let write = if self.is_writable() { 'w' } else { '-' };
        let execute = if self.is_executable() { 'x' } else { '-' };
        write!(f, "{read}{write}{execute}")?;
        if self.is_guarded() {
            f.write_str("+guard")?;
        }
        Ok(())
    }
}

/// Width of a pointer in the target process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PointerWidth {
    /// 32-bit pointers.
    Bits32,
    /// 64-bit pointers.
    Bits64,
}

impl PointerWidth {
    /// Returns the pointer width in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }
}

/// The kind of memory backing a region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegionKind {
    /// A mapped executable image, such as an executable or DLL
    /// (Windows `MEM_IMAGE`).
    ///
    /// The Linux backend does not report this kind: Linux does not expose an
    /// image distinction, so file-backed mappings, including shared libraries,
    /// are reported as [`RegionKind::Mapped`].
    Image,
    /// A file-backed mapping (Linux), or a mapped view (Windows `MEM_MAPPED`).
    Mapped,
    /// An anonymous or private allocation. On Linux this includes the heap,
    /// stacks and other anonymous mappings.
    Private,
}

/// Classification of an [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The target process does not exist, or an enumerated object was not
    /// found.
    NotFound,
    /// The operating system denied access to the process or its memory.
    PermissionDenied,
    /// The process that was opened has exited or its PID was reused.
    ProcessExited,
    /// An address or address range is not valid on this platform.
    InvalidAddress,
    /// A protection combination cannot be represented by this platform.
    InvalidProtection,
    /// The operation is not available on this platform.
    Unsupported,
    /// Data returned by the operating system could not be parsed.
    MalformedData,
    /// Any other operating-system error.
    Other,
}

/// An operating-system failure with its raw error code and classification.
///
/// The [`Display`](fmt::Display) implementation contains the platform message;
/// the standard library embeds the raw code in that message on both supported
/// platforms. The code is also available separately through [`Error::raw_code`].
/// Higher layers attach process, address and length context and expose this type
/// as the error source.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    raw_code: Option<i32>,
    message: String,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, raw_code: Option<i32>, message: impl Into<String>) -> Self {
        Self {
            kind,
            raw_code,
            message: message.into(),
        }
    }

    pub(crate) fn malformed(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::MalformedData, None, message)
    }

    /// Returns the classification of this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the raw platform error code, if the failure came from an
    /// operating-system call.
    ///
    /// This is an `errno` value on Linux and a `GetLastError` code on Windows.
    #[must_use]
    pub fn raw_code(&self) -> Option<i32> {
        self.raw_code
    }

    /// Returns the platform error message without additional context.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// A committed memory region as reported by the operating system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRegion {
    /// First address of the region.
    pub base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Access protection of the region.
    pub protection: Protection,
    /// What backs the region.
    pub kind: RegionKind,
    /// File backing the mapping, when the platform reports one.
    pub path: Option<PathBuf>,
}

/// A process entry as reported by the operating system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawProcessInfo {
    /// Process identifier.
    pub pid: u32,
    /// Process image name, normally the executable file name.
    pub name: String,
    /// Full executable path when the operating system exposes it.
    pub exe_path: Option<PathBuf>,
}

/// A loaded module as reported by the operating system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawModule {
    /// Module name, usually the file name.
    pub name: String,
    /// Full path recorded by the operating system.
    pub path: PathBuf,
    /// Load address of the module.
    pub base: u64,
    /// Size of the module's mapping in bytes.
    pub size: u64,
}

/// Creates the platform message for a raw OS error code.
pub(crate) fn io_message(code: i32) -> String {
    std::io::Error::from_raw_os_error(code).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_flags_are_queryable() {
        let protection = Protection::READ | Protection::EXECUTE | Protection::GUARD;
        assert!(protection.is_readable());
        assert!(!protection.is_writable());
        assert!(protection.is_executable());
        assert!(protection.is_guarded());
        assert_eq!(protection.to_string(), "r-x+guard");
        assert_eq!(Protection::empty().to_string(), "---");
        assert_eq!(Protection::default(), Protection::empty());
    }

    #[test]
    fn error_display_is_the_platform_message() {
        let error = Error::new(ErrorKind::Other, Some(2), io_message(2));
        assert_eq!(error.to_string(), error.message());
    }

    #[test]
    fn protection_supports_set_operations() {
        let readable = Protection::READ;
        let writable = Protection::WRITE;
        assert_eq!(readable | writable, Protection::READ | Protection::WRITE);
        assert!((readable | writable).contains(readable));
        assert!(!readable.contains(Protection::WRITE));
        assert_eq!(Protection::all().bits(), 0b1111);
    }
}

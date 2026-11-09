//! Low-level operating-system bindings used by [`memdiver-core`].
//!
//! This crate is the only place in the workspace that contains platform
//! specific code and `unsafe` blocks. It exposes a deliberately small,
//! handle-based API:
//!
//! * [`ProcessHandle`] pins one process and its memory for its entire lifetime.
//! * Reads and writes report how many bytes the operating system transferred;
//!   deciding whether a short transfer is an error is the caller's job.
//! * [`ProcessHandle::write_code`] performs a scoped code write. On Windows this
//!   temporarily changes page protection and reports write and restoration
//!   failures separately; on Linux it is a plain `/proc/<pid>/mem` write because
//!   Linux has no cross-process protection change.
//! * [`ProcessHandle::read_module_file`] reads a mapped module file in the
//!   target's namespace, bounded to a regular file of at most
//!   [`MAX_MODULE_FILE_SIZE`] bytes.
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
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use bitflags::bitflags;

/// Largest module file this crate will read for export resolution.
///
/// Module files are parsed from disk, so the size is bounded to keep a
/// malicious or accidental mapping of a device, FIFO or enormous sparse file
/// from consuming unbounded memory. A module larger than this cannot have its
/// exports resolved.
pub const MAX_MODULE_FILE_SIZE: u64 = 1024 * 1024 * 1024;

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
    /// The target's address space was replaced, for example by `execve`.
    ///
    /// The process is still alive and its PID and start time are unchanged, but
    /// the pinned memory descriptor refers to the previous address space. Open a
    /// new handle to the process to access the new image.
    AddressSpaceReplaced,
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
///
/// A failed Windows transfer may copy a prefix of the requested range before
/// reporting the failure; [`Error::transferred`] exposes that count so callers
/// can report a partial transfer instead of discarding the prefix.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    raw_code: Option<i32>,
    message: String,
    transferred: Option<usize>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, raw_code: Option<i32>, message: impl Into<String>) -> Self {
        Self {
            kind,
            raw_code,
            message: message.into(),
            transferred: None,
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

    /// Returns the number of bytes the operating-system call transferred before
    /// it failed, when the platform reports one.
    ///
    /// This is `Some` for a Windows `ReadProcessMemory`/`WriteProcessMemory`
    /// failure that copied a prefix of the range; a short *successful* Linux
    /// transfer is returned as a byte count instead. The failure remains an
    /// error either way.
    #[must_use]
    pub fn transferred(&self) -> Option<usize> {
        self.transferred
    }

    #[cfg(any(windows, test))]
    pub(crate) fn with_transferred(mut self, transferred: usize) -> Self {
        self.transferred = Some(transferred);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// A page whose original protection could not be restored after a scoped code
/// write.
///
/// The source is boxed so the composite [`CodeWriteError`] stays small.
#[derive(Debug)]
pub struct RestoreFailure {
    /// Address of the page whose protection could not be restored.
    pub address: u64,
    /// Number of bytes covered by the failed restoration.
    pub len: usize,
    /// Operating-system error from restoring the protection.
    pub source: Box<Error>,
}

/// The step of a scoped code write that failed.
///
/// A [`CodeWriteFailure::Protect`] failure names the page whose protection
/// could not be changed; a [`CodeWriteFailure::Write`] failure covers the whole
/// requested range. The underlying [`Error`] is boxed so this composite type
/// stays small.
#[derive(Debug)]
pub enum CodeWriteFailure {
    /// Changing the protection of one page failed.
    Protect {
        /// Address of the page whose protection change failed.
        address: u64,
        /// Number of bytes covered by the failed protection change.
        len: usize,
        /// Operating-system error from the protection change.
        source: Box<Error>,
    },
    /// Writing the bytes failed.
    Write(Box<Error>),
}

/// The result of a failed [`ProcessHandle::write_code`] call.
///
/// The variants separate the two interesting outcomes: either every protection
/// touched by the operation was restored, or at least one page was left with
/// the temporary protection. A write or protection failure is retained
/// alongside the restore failure so callers can report both.
#[derive(Debug)]
pub enum CodeWriteError {
    /// The write or a protection change failed and every protection that had
    /// already been changed was restored successfully.
    Failed(CodeWriteFailure),
    /// The write succeeded, but at least one page's original protection could
    /// not be restored.
    RestoreFailedAfterWrite {
        /// Number of bytes the operating system reported as written.
        transferred: usize,
        /// The first page whose protection could not be restored.
        restore: RestoreFailure,
        /// Number of further pages whose protection could not be restored.
        additional_restore_failures: usize,
    },
    /// The write or a protection change failed and at least one page's original
    /// protection could not be restored.
    RestoreFailedAfterFailure {
        /// Failure from the protection or write step.
        failure: CodeWriteFailure,
        /// The first page whose protection could not be restored.
        restore: RestoreFailure,
        /// Number of further pages whose protection could not be restored.
        additional_restore_failures: usize,
    },
}

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

/// Reads an already-opened file with a metadata and size guard.
///
/// The file must be a regular file no larger than `max_len` at the time of the
/// metadata check; the subsequent read is capped at `max_len + 1` so a file
/// that grows or a device that never ends cannot consume unbounded memory.
/// `map` converts an I/O failure into the platform-specific [`Error`].
pub(crate) fn read_bounded_file(
    file: File,
    max_len: u64,
    map: fn(std::io::Error) -> Error,
) -> Result<Vec<u8>, Error> {
    let metadata = file.metadata().map_err(map)?;
    if !metadata.is_file() {
        return Err(Error::malformed(
            "module path is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > max_len {
        return Err(Error::malformed(format!(
            "module file is {} bytes, larger than the {max_len}-byte limit",
            metadata.len()
        )));
    }
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| Error::malformed("module file size does not fit in usize".to_owned()))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        Error::new(
            ErrorKind::Other,
            None,
            format!("could not allocate {capacity} bytes for a module file"),
        )
    })?;
    let mut limited = file.take(max_len.saturating_add(1));
    limited.read_to_end(&mut bytes).map_err(map)?;
    if bytes.len() as u64 > max_len {
        return Err(Error::malformed(
            "module file grew while it was being read".to_owned(),
        ));
    }
    Ok(bytes)
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
    fn partial_transfer_count_is_available() {
        assert_eq!(
            Error::new(ErrorKind::Other, None, "failed").transferred(),
            None
        );
        let error = Error::new(ErrorKind::InvalidAddress, Some(299), "partial").with_transferred(7);
        assert_eq!(error.transferred(), Some(7));
        assert_eq!(error.kind(), ErrorKind::InvalidAddress);
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

    fn test_io_error(error: std::io::Error) -> Error {
        Error::new(ErrorKind::Other, error.raw_os_error(), error.to_string())
    }

    #[test]
    fn bounded_file_read_enforces_regular_file_and_size() {
        let path = std::env::temp_dir().join(format!(
            "memdiver-sys-bounded-{}-{}",
            std::process::id(),
            std::line!()
        ));
        std::fs::write(&path, b"hello").expect("write temporary file");

        let error = read_bounded_file(
            File::open(&path).expect("open temporary file"),
            4,
            test_io_error,
        )
        .expect_err("a five-byte file must exceed a four-byte limit");
        assert_eq!(error.kind(), ErrorKind::MalformedData);

        let bytes = read_bounded_file(
            File::open(&path).expect("open temporary file"),
            5,
            test_io_error,
        )
        .expect("exactly the size limit must be accepted");
        assert_eq!(bytes, b"hello");
        let _ = std::fs::remove_file(&path);

        #[cfg(unix)]
        {
            let device = File::open("/dev/zero").expect("open /dev/zero");
            let error = read_bounded_file(device, 16, test_io_error)
                .expect_err("/dev/zero is not a regular file");
            assert_eq!(error.kind(), ErrorKind::MalformedData);
        }
    }
}

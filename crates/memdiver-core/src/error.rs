//! Errors returned by the safe API.

use memdiver_sys::Error as OsError;
use memdiver_sys::ErrorKind as OsErrorKind;

use crate::{Address, ProcessInfo, Protection};

/// The error type returned by all memory operations.
///
/// Every operating-system failure keeps its [`OsError`] as the error source and
/// is wrapped in context identifying the process, address, and length that were
/// involved. The enum is non-exhaustive so new failure modes can be added
/// without a breaking release.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The process does not exist.
    #[error("process {pid} does not exist")]
    ProcessNotFound {
        /// PID that could not be opened.
        pid: u32,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// The operating system denied access to the process.
    ///
    /// On Linux this usually means the ptrace access check failed. On Windows it
    /// means `OpenProcess` returned `ERROR_ACCESS_DENIED`.
    #[error("access to process {pid} was denied")]
    AccessDenied {
        /// PID that could not be opened.
        pid: u32,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// The process could not be opened for another reason.
    #[error("failed to open process {pid}: {source}")]
    Open {
        /// PID that could not be opened.
        pid: u32,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// A memory read failed.
    #[error("failed to read {len} bytes at {address} from process {pid}: {source}")]
    Read {
        /// PID of the target process.
        pid: u32,
        /// Address that was being read.
        address: Address,
        /// Number of bytes requested.
        len: usize,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// A memory write failed.
    #[error("failed to write {len} bytes at {address} to process {pid}: {source}")]
    Write {
        /// PID of the target process.
        pid: u32,
        /// Address that was being written.
        address: Address,
        /// Number of bytes requested.
        len: usize,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// The operating system transferred fewer bytes than requested.
    ///
    /// The caller's buffer may contain a partial result up to `transferred`
    /// bytes; the library never silently truncates a successful transfer.
    #[error(
        "short read at {address} in process {pid}: transferred {transferred} of {requested} bytes"
    )]
    PartialRead {
        /// PID of the target process.
        pid: u32,
        /// Address that was being read.
        address: Address,
        /// Number of bytes requested.
        requested: usize,
        /// Number of bytes actually transferred.
        transferred: usize,
    },

    /// The operating system wrote fewer bytes than requested.
    #[error(
        "short write at {address} in process {pid}: transferred {transferred} of {requested} bytes"
    )]
    PartialWrite {
        /// PID of the target process.
        pid: u32,
        /// Address that was being written.
        address: Address,
        /// Number of bytes requested.
        requested: usize,
        /// Number of bytes actually transferred.
        transferred: usize,
    },

    /// Enumerating memory regions or modules failed.
    #[error("failed to enumerate {what} for process {pid}: {source}")]
    Enumerate {
        /// PID of the target process.
        pid: u32,
        /// What was being enumerated.
        what: &'static str,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// Changing memory protection failed.
    #[error("failed to change protection of {len} bytes at {address} in process {pid}: {source}")]
    Protect {
        /// PID of the target process.
        pid: u32,
        /// Start of the range.
        address: Address,
        /// Number of bytes in the range.
        len: usize,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// The operation is not available on this platform.
    #[error("{operation} is not supported on this platform: {reason}")]
    Unsupported {
        /// Operation that was attempted.
        operation: &'static str,
        /// Why the platform cannot perform it.
        reason: &'static str,
    },

    /// The address range is invalid because it overflows the address space.
    #[error("address range starting at {address} with length {len} is invalid")]
    AddressRange {
        /// Start of the range.
        address: Address,
        /// Length of the range.
        len: usize,
    },

    /// The operation requires a non-empty range.
    #[error("{operation} requires a non-empty range, but the length was {len}")]
    InvalidLength {
        /// Operation that rejected the length.
        operation: &'static str,
        /// Length that was supplied.
        len: usize,
    },

    /// The requested protection cannot be represented by the platform.
    #[error("protection {protection} cannot be applied to process memory")]
    InvalidProtection {
        /// Protection that was requested.
        protection: Protection,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// Allocating a buffer for a read failed.
    #[error("could not allocate a {len}-byte read buffer")]
    Allocation {
        /// Number of bytes requested.
        len: usize,
        /// Allocation failure.
        #[source]
        source: std::collections::TryReserveError,
    },

    /// No process matched the requested name.
    #[error("no process named {name:?} was found")]
    ProcessNameNotFound {
        /// Name that was searched for.
        name: String,
    },

    /// More than one process matched the requested name.
    #[error("process name {name:?} matches multiple processes; select one by PID")]
    AmbiguousProcessName {
        /// Name that was searched for.
        name: String,
        /// Matching process entries.
        candidates: Vec<ProcessInfo>,
    },

    /// The process identity changed while it was being opened by name.
    #[error("process {name:?} exited or was replaced while it was being opened")]
    ProcessChanged {
        /// Name that was being opened.
        name: String,
    },

    /// The handle was opened without write access.
    #[error("process {pid} was opened read-only; {operation} requires write access")]
    ReadOnly {
        /// PID of the target process.
        pid: u32,
        /// Operation that was rejected.
        operation: &'static str,
    },

    /// Enumerating processes failed.
    #[error("failed to enumerate processes: {source}")]
    ProcessList {
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// A module file could not be read for export resolution.
    #[error("failed to read module {module:?} from {path:?}: {source}")]
    ModuleFile {
        /// Module whose file was read.
        module: String,
        /// Path that was read.
        path: std::path::PathBuf,
        /// Filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// A module file could not be parsed for export resolution.
    #[error("failed to parse exports for module {module:?}: {reason}")]
    ModuleExports {
        /// Module that was being parsed.
        module: String,
        /// Description of the parse or format failure.
        reason: String,
    },

    /// Waiting for the process failed.
    #[error("failed while waiting for process {pid}: {source}")]
    Wait {
        /// PID of the target process.
        pid: u32,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// Enabling a process privilege failed.
    #[error("failed to enable a process privilege: {source}")]
    Privilege {
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },

    /// A batched read failed at one entry.
    #[error("failed to read batch entry {index} at {address} ({len} bytes): {source}")]
    BatchRead {
        /// Zero-based index in the batch.
        index: usize,
        /// Address of the failed entry.
        address: Address,
        /// Requested length of the failed entry.
        len: usize,
        /// Underlying read error.
        #[source]
        source: Box<Error>,
    },

    /// A batched write failed at one entry.
    #[error("failed to write batch entry {index} at {address} ({len} bytes): {source}")]
    BatchWrite {
        /// Zero-based index in the batch.
        index: usize,
        /// Address of the failed entry.
        address: Address,
        /// Requested length of the failed entry.
        len: usize,
        /// Underlying write error.
        #[source]
        source: Box<Error>,
    },

    /// A scoped code write failed and the original page protection could not
    /// be fully restored.
    ///
    /// This combines the protection or write failure with the failure to
    /// restore the first page whose protection was left modified. Use
    /// [`Error::CodeWriteRestore`] when the write itself succeeded but
    /// restoration failed.
    #[error(
        "failed to write {len} bytes of code at {address} in process {pid}: {failure}; restoring the original protection also failed: {restore} ({additional_restore_failures} additional page restoration failure(s))"
    )]
    CodeWrite {
        /// PID of the target process.
        pid: u32,
        /// Start of the code range.
        address: Address,
        /// Number of bytes requested.
        len: usize,
        /// Failure from the write or protection step.
        #[source]
        failure: Box<Error>,
        /// Failure restoring the first page that could not be restored.
        restore: Box<Error>,
        /// Number of further pages whose protection could not be restored.
        additional_restore_failures: usize,
    },

    /// A scoped code write completed, but the original page protection could
    /// not be fully restored.
    ///
    /// The write transferred the bytes successfully; the only failure is the
    /// attempted restoration of a page's previous protection.
    #[error(
        "wrote {transferred} of {len} bytes of code at {address} in process {pid}, but restoring the original protection failed: {restore} ({additional_restore_failures} additional page restoration failure(s))"
    )]
    CodeWriteRestore {
        /// PID of the target process.
        pid: u32,
        /// Start of the code range.
        address: Address,
        /// Number of bytes requested.
        len: usize,
        /// Number of bytes actually written.
        transferred: usize,
        /// Failure restoring the first page that could not be restored.
        #[source]
        restore: Box<Error>,
        /// Number of further pages whose protection could not be restored.
        additional_restore_failures: usize,
    },

    /// A pointer chain overflowed the target's address width.
    #[error("pointer chain overflow at {address} while adding {offset:#x} in process {pid}")]
    PointerChainOverflow {
        /// PID of the target process.
        pid: u32,
        /// Pointer value before the addition that overflowed.
        address: Address,
        /// Offset that could not be added.
        offset: u64,
    },

    /// A byte pattern could not be parsed.
    #[error("invalid pattern: {reason}")]
    InvalidPattern {
        /// Human-readable reason for the parse failure.
        reason: String,
    },

    /// No loaded module matched the requested name.
    #[error("module {name:?} is not loaded in the target process")]
    ModuleNotFound {
        /// Module name that was requested.
        name: String,
    },

    /// Querying process metadata failed.
    #[error("failed to query {what} for process {pid}: {source}")]
    Query {
        /// PID of the target process.
        pid: u32,
        /// What was being queried.
        what: &'static str,
        /// Underlying operating-system error.
        #[source]
        source: OsError,
    },
}

/// Result alias used by the library.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn open_error(pid: u32, source: OsError) -> Error {
    match source.kind() {
        OsErrorKind::NotFound => Error::ProcessNotFound { pid, source },
        OsErrorKind::PermissionDenied => Error::AccessDenied { pid, source },
        _ => Error::Open { pid, source },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_context() {
        let error = Error::PartialRead {
            pid: 42,
            address: Address::new(0x1000),
            requested: 16,
            transferred: 8,
        };
        let message = error.to_string();
        assert!(message.contains("0x1000"));
        assert!(message.contains("process 42"));
        assert!(message.contains("8 of 16"));
    }

    #[test]
    fn unsupported_display_mentions_platform() {
        let error = Error::Unsupported {
            operation: "Process::protect",
            reason: "the OS does not allow it",
        };
        assert_eq!(
            error.to_string(),
            "Process::protect is not supported on this platform: the OS does not allow it"
        );
    }

    #[test]
    fn alloc_error_preserves_length() {
        let mut bytes = Vec::<u8>::new();
        let source = bytes
            .try_reserve_exact(usize::MAX)
            .expect_err("reservation must fail");
        let error = Error::Allocation {
            len: usize::MAX,
            source,
        };
        assert!(error.to_string().contains("read buffer"));
    }

    #[test]
    fn code_write_error_keeps_both_failures_and_context() {
        let address = Address::new(0x1000);
        let write = Error::PartialWrite {
            pid: 42,
            address,
            requested: 16,
            transferred: 8,
        };
        // The production restore failure is `Error::Protect`, but building that
        // variant needs an `OsError` from an operating-system call. This unit
        // test focuses on composition and formatting, so a structural error
        // with a page address stands in for the restore failure.
        let restore = Error::AddressRange {
            address: Address::new(0x2000),
            len: 0x1000,
        };
        let error = Error::CodeWrite {
            pid: 42,
            address,
            len: 16,
            failure: Box::new(write),
            restore: Box::new(restore),
            additional_restore_failures: 2,
        };
        let message = error.to_string();
        assert!(message.contains("process 42"), "{message}");
        assert!(message.contains("0x1000"), "{message}");
        assert!(message.contains("8 of 16"), "{message}");
        assert!(message.contains("0x2000"), "{message}");
        assert!(message.contains("2 additional"), "{message}");
        let source = std::error::Error::source(&error).expect("write failure must be the source");
        assert!(source.to_string().contains("8 of 16"), "{source}");

        // A restore failure after a successful write is a distinct variant so
        // callers can tell that the bytes were transferred and only protection
        // is at risk. The OS has no reliable way to force VirtualProtectEx to
        // fail only during restoration, so the composite construction and
        // formatting is covered here rather than in an end-to-end test.
        let restore = Error::AddressRange {
            address: Address::new(0x3000),
            len: 0x1000,
        };
        let error = Error::CodeWriteRestore {
            pid: 42,
            address,
            len: 16,
            transferred: 16,
            restore: Box::new(restore),
            additional_restore_failures: 0,
        };
        let message = error.to_string();
        assert!(message.contains("wrote 16 of 16"), "{message}");
        assert!(message.contains("0x3000"), "{message}");
        let source = std::error::Error::source(&error).expect("restore failure must be the source");
        assert!(source.to_string().contains("0x3000"), "{source}");
    }
}

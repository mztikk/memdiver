//! Errors returned by the safe API.

use memoria_sys::Error as OsError;
use memoria_sys::ErrorKind as OsErrorKind;

use crate::{Address, Protection};

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
}

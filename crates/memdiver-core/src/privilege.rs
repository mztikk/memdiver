//! Process privilege helpers.

use memdiver_sys::ErrorKind as OsErrorKind;

use crate::{Error, Result};

/// Enables the current process's debug privilege.
///
/// On Windows this enables `SeDebugPrivilege`, which many protected or
/// higher-integrity processes require. The caller must normally be an
/// administrator; enabling the privilege does not guarantee access, and the
/// function is intentionally opt-in. On Linux this returns
/// [`Error::Unsupported`] because ptrace permissions are the equivalent control.
///
/// # Errors
///
/// Returns [`Error::Privilege`] for Windows token or privilege failures and
/// [`Error::Unsupported`] on Linux.
pub fn enable_debug_privilege() -> Result<()> {
    memdiver_sys::enable_debug_privilege().map_err(|source| match source.kind() {
        OsErrorKind::Unsupported => Error::Unsupported {
            operation: "enabling debug privilege",
            reason: "Linux uses ptrace permissions instead of a process privilege",
        },
        _ => Error::Privilege { source },
    })
}

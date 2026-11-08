//! Waiting for process exit.

use std::time::Duration;

use crate::{Error, Process, Result};

impl Process {
    /// Waits for the process to exit.
    ///
    /// Returns `true` if the process exited and `false` if the timeout expired
    /// first. Pass `None` to wait indefinitely.
    ///
    /// On Linux this waits on a pinned pidfd when available (Linux 5.3+), so a
    /// long wait consumes no periodic wakeups. Older kernels or hosts where
    /// `pidfd_open` is blocked fall back to polling the pinned procfs handle
    /// with start-time verification. PID reuse is never mistaken for the
    /// original process exiting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Wait`] when the platform wait operation fails.
    pub fn wait_for_exit(&self, timeout: Option<Duration>) -> Result<bool> {
        self.inner
            .wait_for_exit(timeout)
            .map_err(|source| Error::Wait {
                pid: self.pid,
                source,
            })
    }
}

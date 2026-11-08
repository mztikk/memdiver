//! Waiting for process exit.

use std::time::Duration;

use crate::{Error, Process, Result};

impl Process {
    /// Waits for the process to exit.
    ///
    /// Returns `true` if the process exited and `false` if the timeout expired
    /// first. Pass `None` to wait indefinitely. On Linux this polls the pinned
    /// procfs handle and verifies the process start time, so PID reuse is not
    /// mistaken for the original process exiting.
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

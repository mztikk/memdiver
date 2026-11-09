//! Process discovery and identity.

use std::path::{Path, PathBuf};

use memdiver_sys::RawProcessInfo;

/// A process entry returned by [`Process::list`](crate::Process::list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pid: u32,
    name: String,
    exe_path: Option<PathBuf>,
    start_time: Option<u64>,
}

impl ProcessInfo {
    pub(crate) fn from_raw(raw: RawProcessInfo) -> Self {
        Self {
            pid: raw.pid,
            name: raw.name,
            exe_path: raw.exe_path,
            start_time: raw.start_time,
        }
    }

    /// Returns the process identifier.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the process image name.
    ///
    /// This is normally the executable file name. On Linux it comes from the
    /// executable link when available and falls back to `/proc/<pid>/comm`.
    /// Names that are not valid Unicode are converted lossily (including
    /// invalid UTF-16 on Windows); use [`ProcessInfo::exe_path`] when exact
    /// path bytes matter. Windows paths are preserved as WTF-16.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the executable path when the operating system exposes it.
    #[must_use]
    pub fn exe_path(&self) -> Option<&Path> {
        self.exe_path.as_deref()
    }

    /// Returns the opaque process-instance identity captured during enumeration.
    ///
    /// On Linux this is the start time from `/proc/<pid>/stat`; on Windows it is
    /// the process creation time. Compare it only with another value from the
    /// same platform. `None` means the identity could not be read; such an entry
    /// cannot be verified by [`Process::open_by_name`](crate::Process::open_by_name).
    #[must_use]
    pub fn start_time(&self) -> Option<u64> {
        self.start_time
    }

    /// Returns `true` when this entry matches `name`.
    ///
    /// Matching is case-sensitive on Linux and ASCII case-insensitive on
    /// Windows, mirroring the native process naming rules. The executable file
    /// name is also considered when the platform reported one.
    #[must_use]
    pub fn matches_name(&self, name: &str) -> bool {
        name_matches(&self.name, name)
            || self
                .exe_path
                .as_deref()
                .and_then(Path::file_name)
                .is_some_and(|file_name| name_matches(&file_name.to_string_lossy(), name))
    }
}

pub(crate) fn name_matches(actual: &str, requested: &str) -> bool {
    #[cfg(windows)]
    {
        actual.eq_ignore_ascii_case(requested)
    }
    #[cfg(not(windows))]
    {
        actual == requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(name: &str, path: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 42,
            name: name.to_owned(),
            exe_path: path.map(PathBuf::from),
            start_time: Some(1),
        }
    }

    #[test]
    fn exposes_fields() {
        let process = info("game.exe", Some("/opt/game/game.exe"));
        assert_eq!(process.pid(), 42);
        assert_eq!(process.name(), "game.exe");
        assert_eq!(process.exe_path(), Some(Path::new("/opt/game/game.exe")));
        assert_eq!(process.start_time(), Some(1));
    }

    #[test]
    fn matches_name_using_platform_case_rules() {
        let process = info("game.exe", Some("/opt/game/game.exe"));
        assert!(process.matches_name("game.exe"));

        #[cfg(windows)]
        assert!(process.matches_name("GAME.EXE"));
        #[cfg(not(windows))]
        assert!(!process.matches_name("GAME.EXE"));
    }

    #[test]
    fn matches_executable_file_name() {
        let process = info("renamed", Some("/opt/game/game.exe"));
        assert!(process.matches_name("game.exe"));
        assert!(!process.matches_name("other.exe"));
    }
}

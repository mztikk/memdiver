//! Linux backend built on `/proc/<pid>/mem` and `/proc/<pid>/maps`.
//!
//! A [`ProcessHandle`] pins four things for its lifetime:
//!
//! * the `/proc/<pid>` directory file descriptor,
//! * the `/proc/<pid>/mem` file descriptor,
//! * the process start time from `/proc/<pid>/stat`, and
//! * a `pidfd` when the kernel supports `pidfd_open`.
//!
//! The memory file descriptor refers to the memory map that existed when it was
//! opened. The start time lets the handle detect PID reuse for the queries that
//! have to reopen procfs files (maps and stat). This is why the handle never
//! performs a read by PID alone. A target `execve` keeps the PID and start time
//! but installs a new address space; the pinned descriptor then returns zero
//! bytes and reads report [`ErrorKind::AddressSpaceReplaced`].

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::{
    CodeWriteError, CodeWriteFailure, Error, ErrorKind, PointerWidth, Protection, RawModule,
    RawProcessInfo, RawRegion, RegionKind, io_message,
};

const COMM: &CStr = c"comm";
const EXE: &CStr = c"exe";
const MEM: &CStr = c"mem";
const STAT: &CStr = c"stat";
const MAPS: &CStr = c"maps";

/// A pinned handle to a Linux process.
///
/// Created with [`ProcessHandle::open`]. Dropping the handle closes the procfs
/// descriptors but never terminates the target process.
pub struct ProcessHandle {
    pid: u32,
    proc_dir: File,
    mem: File,
    start_time: u64,
    pidfd: Option<File>,
}

impl fmt::Debug for ProcessHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessHandle")
            .field("pid", &self.pid)
            .field("start_time", &self.start_time)
            .field("pidfd", &self.pidfd.is_some())
            .finish_non_exhaustive()
    }
}

impl ProcessHandle {
    /// Opens a handle to the process with the given PID.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::NotFound`] when the process does not exist,
    /// [`ErrorKind::PermissionDenied`] when the ptrace access check denies the
    /// caller, [`ErrorKind::ProcessExited`] when the process exits or its PID is
    /// reused during open, and [`ErrorKind::MalformedData`] when procfs data
    /// cannot be parsed.
    pub fn open(pid: u32) -> Result<Self, Error> {
        Self::open_with(pid, true)
    }

    /// Opens a handle to the process with the given PID.
    ///
    /// When `writable` is false the memory file is opened read-only and write
    /// calls fail at the operating-system level. Higher layers should reject
    /// writes before reaching this point.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::NotFound`] when the process does not exist,
    /// [`ErrorKind::PermissionDenied`] when the ptrace access check denies the
    /// caller, [`ErrorKind::ProcessExited`] when the process exits or its PID is
    /// reused during open, and [`ErrorKind::MalformedData`] when procfs data
    /// cannot be parsed.
    pub fn open_with(pid: u32, writable: bool) -> Result<Self, Error> {
        let proc_dir = File::open(format!("/proc/{pid}")).map_err(io_error)?;

        // Read the identity before and after opening the memory file. If the
        // PID is recycled during open, the start times differ and the handle is
        // rejected instead of combining one process's memory with another
        // process's metadata.
        let before = read_stat(&proc_dir, pid)?;
        let flags = if writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        let mem = open_proc_file(&proc_dir, MEM, flags).map_err(io_error)?;
        let after = read_stat(&proc_dir, pid)?;
        if before.start_time != after.start_time || is_dead_state(after.state) {
            return Err(process_exited(pid));
        }

        let pidfd = open_verified_pidfd(pid, &proc_dir, after.start_time);
        Ok(Self {
            pid,
            proc_dir,
            mem,
            start_time: after.start_time,
            pidfd,
        })
    }

    /// Returns the PID this handle was opened for.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the opaque process-instance identity captured at open time.
    ///
    /// This is the start time from `/proc/<pid>/stat`. It is stable for the
    /// lifetime of the process instance and changes when the PID is reused.
    #[must_use]
    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    /// Returns the pointer width of the target process, derived from the ELF
    /// class of its executable.
    ///
    /// # Errors
    ///
    /// Returns an error when the executable cannot be read or its ELF header is
    /// malformed.
    pub fn pointer_width(&self) -> Result<PointerWidth, Error> {
        let mut file = open_proc_file(&self.proc_dir, EXE, libc::O_RDONLY).map_err(io_error)?;
        let mut header = [0u8; 5];
        file.read_exact(&mut header).map_err(io_error)?;
        if header.get(..4) != Some(b"\x7fELF") {
            return Err(Error::malformed(
                "process executable does not start with an ELF header",
            ));
        }
        match header[4] {
            1 => Ok(PointerWidth::Bits32),
            2 => Ok(PointerWidth::Bits64),
            class => Err(Error::malformed(format!(
                "unknown ELF class {class} for process executable"
            ))),
        }
    }

    /// Returns the executable path recorded by the kernel, when available.
    ///
    /// A trailing `" (deleted)"` marker is removed. `None` is returned when the
    /// process has no executable or the kernel does not expose the link.
    ///
    /// # Errors
    ///
    /// Returns an error for unexpected procfs failures.
    pub fn exe_path(&self) -> Result<Option<PathBuf>, Error> {
        match read_link_at(&self.proc_dir, EXE) {
            Ok(path) => Ok(Some(strip_deleted(path))),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(io_error(error)),
        }
    }

    /// Reads up to `buffer.len()` bytes starting at `address`.
    ///
    /// Returns the number of bytes transferred. A short transfer is not an
    /// error at this layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the address range cannot be represented as a
    /// procfs file offset or when the kernel rejects the read.
    pub fn read(&self, address: u64, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let offset = procfs_offset(address, buffer.len())?;
        let transferred = pread(&self.mem, buffer, offset).map_err(mem_io_error)?;
        if transferred == 0 {
            return Err(self.zero_transfer_error(address, buffer.len()));
        }
        Ok(transferred)
    }

    /// Writes up to `buffer.len()` bytes starting at `address`.
    ///
    /// Returns the number of bytes transferred. A short transfer is not an
    /// error at this layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the address range cannot be represented as a
    /// procfs file offset or when the kernel rejects the write.
    pub fn write(&self, address: u64, buffer: &[u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let offset = procfs_offset(address, buffer.len())?;
        let transferred = pwrite(&self.mem, buffer, offset).map_err(mem_io_error)?;
        if transferred == 0 {
            return Err(self.zero_transfer_error(address, buffer.len()));
        }
        Ok(transferred)
    }

    /// Writes `buffer` at `address` and returns the number of bytes transferred.
    ///
    /// Linux does not allow one process to change another process's page
    /// protections, and a write through `/proc/<pid>/mem` does not need a
    /// protection change. This is therefore a plain [`ProcessHandle::write`];
    /// the scoped code-write guarantees reduce to the normal write result.
    ///
    /// The write does not synchronize the target's instruction cache. On x86
    /// and x86_64 the instruction and data caches are coherent; on other
    /// architectures, including ARM64, the target may execute stale
    /// instructions. No cache-flush operation is provided yet.
    ///
    /// # Errors
    ///
    /// Returns [`CodeWriteError::Failed`] with [`CodeWriteFailure::Write`] for
    /// any write error.
    pub fn write_code(&self, address: u64, buffer: &[u8]) -> Result<usize, CodeWriteError> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.write(address, buffer)
            .map_err(|source| CodeWriteError::Failed(CodeWriteFailure::Write(Box::new(source))))
    }

    /// Returns whether the process is still running.
    ///
    /// A zombie or dead process is reported as not alive, as is a process whose
    /// PID has been reused since the handle was opened. Errors while reading
    /// procfs are treated as "not alive".
    #[must_use]
    pub fn is_alive(&self) -> bool {
        match self.current_stat() {
            Ok(stat) => stat.start_time == self.start_time && !is_dead_state(stat.state),
            Err(_) => false,
        }
    }

    /// Waits for the process to exit.
    ///
    /// Returns `true` when the process has exited and `false` when the timeout
    /// expires first. `None` waits indefinitely.
    ///
    /// On kernels with `pidfd_open` (Linux 5.3+) this blocks in `poll` on a
    /// pinned pidfd and wakes only when the process exits or the timeout
    /// expires. Older kernels, or hosts whose seccomp policy denies
    /// `pidfd_open`, fall back to polling `/proc/<pid>/stat` every 10 ms with
    /// start-time verification.
    ///
    /// # Errors
    ///
    /// Returns an error when `poll` fails on a usable pidfd. In the polling
    /// fallback, procfs read failures are treated as process exit by
    /// [`ProcessHandle::is_alive`].
    pub fn wait_for_exit(&self, timeout: Option<Duration>) -> Result<bool, Error> {
        match &self.pidfd {
            Some(pidfd) => poll_pidfd(pidfd.as_raw_fd(), timeout),
            None => self.wait_for_exit_polling(timeout),
        }
    }

    fn wait_for_exit_polling(&self, timeout: Option<Duration>) -> Result<bool, Error> {
        const POLL_INTERVAL: Duration = Duration::from_millis(10);

        let Some(timeout) = timeout else {
            while self.is_alive() {
                thread::sleep(POLL_INTERVAL);
            }
            return Ok(true);
        };
        if !self.is_alive() {
            return Ok(true);
        }
        let started = Instant::now();
        loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Ok(!self.is_alive());
            }
            thread::sleep((timeout - elapsed).min(POLL_INTERVAL));
            if !self.is_alive() {
                return Ok(true);
            }
        }
    }

    /// Enumerates the committed memory regions of the process.
    ///
    /// # Errors
    ///
    /// Returns an error when the process exited, PID reuse is detected, or
    /// `/proc/<pid>/maps` cannot be read or parsed.
    pub fn regions(&self) -> Result<Vec<RawRegion>, Error> {
        self.ensure_same_process()?;
        let data = read_proc_file(&self.proc_dir, MAPS)?;
        let entries = parse_maps(&data, self.pid)?;
        // Check again after reading: a PID reused while `/proc/<pid>/maps` was
        // open would otherwise produce regions that belong to another process.
        self.ensure_same_process()?;
        Ok(entries.into_iter().map(|entry| entry.region).collect())
    }

    /// Enumerates committed regions without resolving module paths.
    ///
    /// Linux always parses the pathname while reading `/proc/<pid>/maps`, so
    /// this is equivalent to [`ProcessHandle::regions`]; it exists for API
    /// parity with the Windows backend and for scan callers that do not need
    /// paths.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ProcessHandle::regions`].
    pub fn regions_without_paths(&self) -> Result<Vec<RawRegion>, Error> {
        self.regions()
    }

    /// Enumerates the executable modules loaded by the process.
    ///
    /// On Linux a module is a file-backed mapping with at least one executable
    /// segment. Mappings are merged by `(device, inode)`, so all mappings of one
    /// file form one module whose base is the lowest mapping address. Distinct
    /// files that happen to share a path (for example a deleted mapping and its
    /// replacement) are separate modules.
    ///
    /// # Errors
    ///
    /// Returns an error when the process exited, PID reuse is detected, or
    /// `/proc/<pid>/maps` cannot be read or parsed.
    pub fn modules(&self) -> Result<Vec<RawModule>, Error> {
        self.ensure_same_process()?;
        let data = read_proc_file(&self.proc_dir, MAPS)?;
        let entries = parse_maps(&data, self.pid)?;
        self.ensure_same_process()?;
        Ok(modules_from_entries(&entries))
    }

    /// Reads a mapped module file through the target's root and returns its
    /// bytes.
    ///
    /// The path is the one `/proc/<pid>/maps` reported, opened relative to the
    /// pinned `/proc/<pid>` directory descriptor (`root/...`), so it is
    /// interpreted inside the target's mount namespace and cannot be redirected
    /// by PID reuse. The opened file must be a regular file no larger than
    /// [`MAX_MODULE_FILE_SIZE`](crate::MAX_MODULE_FILE_SIZE), and its inode
    /// must still match the mapping (the reported device can differ under
    /// overlay/Btrfs, so the inode is the stable identity). This rejects device
    /// files, FIFOs, huge files and replaced files before any parsing.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::MalformedData`] when the mapping disappeared, the
    /// file is not a regular file, is too large, or changed since it was
    /// mapped. Operating-system errors from opening or reading the file are
    /// preserved.
    pub fn read_module_file(&self, base: u64, path: &Path) -> Result<Vec<u8>, Error> {
        self.ensure_same_process()?;
        let data = read_proc_file(&self.proc_dir, MAPS)?;
        let entries = parse_maps(&data, self.pid)?;
        self.ensure_same_process()?;

        let entry = entries
            .iter()
            .find(|entry| {
                entry.region.path.as_deref() == Some(path)
                    && entry.region.base <= base
                    && base < entry.region.base.saturating_add(entry.region.size)
            })
            .ok_or_else(|| {
                Error::malformed(format!(
                    "module mapping for {} is no longer present",
                    path.display()
                ))
            })?;
        let file_id = entry.file_id.ok_or_else(|| {
            Error::malformed(format!(
                "module mapping for {} has no file identity",
                path.display()
            ))
        })?;

        let relative = target_relative_module_path(path)?;
        let file = open_proc_file(&self.proc_dir, &relative, libc::O_RDONLY).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        // Compare the inode rather than `(st_dev, st_ino)`: overlayfs and btrfs
        // subvolumes can report a different `st_dev` for the path than for the
        // mapping while the inode is stable. A replacement file cannot reuse
        // the inode while the target still maps the old file, so the inode is
        // the reliable identity here.
        if metadata.ino() != file_id.inode {
            return Err(Error::malformed(format!(
                "module file {} changed since it was mapped",
                path.display()
            )));
        }
        crate::read_bounded_file(file, crate::MAX_MODULE_FILE_SIZE, io_error)
    }

    /// Changes the protection of a memory range.
    ///
    /// Linux does not provide a way for one process to change another process's
    /// page protections. This method always returns
    /// [`ErrorKind::Unsupported`]. [`ProcessHandle::write_code`] remains
    /// available because `/proc/<pid>/mem` writes do not need a protection
    /// change.
    ///
    /// # Errors
    ///
    /// Always returns [`ErrorKind::Unsupported`] on Linux.
    pub fn protect(
        &self,
        _address: u64,
        _len: usize,
        _protection: Protection,
    ) -> Result<Protection, Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            None,
            "changing another process's page protection is not supported on Linux",
        ))
    }

    /// Builds the error for a zero-byte transfer on a non-empty request.
    ///
    /// A live process with an unchanged start time but a zero-byte transfer has
    /// replaced its address space (typically via `execve`): the pinned
    /// `/proc/<pid>/mem` descriptor refers to the previous `mm`. A process that
    /// is gone is reported as exited instead.
    fn zero_transfer_error(&self, address: u64, len: usize) -> Error {
        if self.is_alive() {
            Error::new(
                ErrorKind::AddressSpaceReplaced,
                None,
                format!(
                    "process {} replaced its address space before a {len}-byte access at {address:#x}; reopen the process",
                    self.pid
                ),
            )
        } else {
            process_exited(self.pid)
        }
    }

    fn current_stat(&self) -> Result<Stat, Error> {
        read_stat(&self.proc_dir, self.pid)
    }

    fn ensure_same_process(&self) -> Result<(), Error> {
        match self.current_stat() {
            Ok(stat) if stat.start_time == self.start_time && !is_dead_state(stat.state) => Ok(()),
            Ok(_) => Err(process_exited(self.pid)),
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::ProcessExited) =>
            {
                Err(process_exited(self.pid))
            }
            Err(error) => Err(error),
        }
    }
}

/// Enumerates visible processes.
///
/// The list is sorted by PID. Individual processes that exit or cannot be
/// inspected are skipped rather than failing the whole enumeration.
///
/// # Errors
///
/// Returns an error when `/proc` itself cannot be read.
pub fn processes() -> Result<Vec<RawProcessInfo>, Error> {
    let entries = std::fs::read_dir("/proc").map_err(io_error)?;
    let mut processes = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == 0 {
            continue;
        }
        if let Some(info) = process_info(pid) {
            processes.push(info);
        }
    }
    processes.sort_by_key(|process| process.pid);
    Ok(processes)
}

fn process_info(pid: u32) -> Option<RawProcessInfo> {
    let dir = File::open(format!("/proc/{pid}")).ok()?;
    // Read the identity before the name so a process that is replaced during
    // enumeration does not pair the old name with the new instance's start time.
    let start_time = read_stat(&dir, pid).ok().map(|stat| stat.start_time);
    let exe_path = read_link_at(&dir, EXE).ok().map(strip_deleted);
    let exe_name = exe_path
        .as_deref()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned());
    // Only read `comm` when the executable name did not decide the result; in
    // the common case this saves an open/read/close per process.
    let name = match exe_name {
        Some(name) => name,
        None => read_comm(&dir)?,
    };
    Some(RawProcessInfo {
        pid,
        name,
        exe_path,
        start_time,
    })
}

fn read_comm(dir: &File) -> Option<String> {
    let data = read_proc_file(dir, COMM).ok()?;
    let end = data
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(data.len());
    let name = String::from_utf8_lossy(data.get(..end)?).into_owned();
    (!name.is_empty()).then_some(name)
}

fn strip_deleted(path: PathBuf) -> PathBuf {
    let bytes = path.into_os_string().into_vec();
    let stripped = bytes.strip_suffix(b" (deleted)").unwrap_or(&bytes);
    PathBuf::from(OsString::from_vec(stripped.to_vec()))
}

fn read_link_at(dir: &File, name: &CStr) -> io::Result<PathBuf> {
    let mut capacity = 256;
    loop {
        let mut buffer = vec![0u8; capacity];
        // SAFETY: `dir` is an open directory descriptor, `name` is a valid
        // NUL-terminated name relative to it, and `buffer` is writable for
        // `capacity` bytes. readlinkat does not add a NUL terminator.
        let length = unsafe {
            libc::readlinkat(
                dir.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = length as usize;
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(PathBuf::from(OsString::from_vec(buffer)));
        }
        capacity = capacity
            .checked_mul(2)
            .filter(|capacity| *capacity <= 1024 * 1024)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "process executable path is unreasonably long",
                )
            })?;
    }
}

/// Enables debug privileges.
///
/// Debug privileges are a Windows concept. On Linux the equivalent control is
/// the ptrace access check (`kernel.yama.ptrace_scope`, capabilities, or the
/// target opting in with `PR_SET_PTRACER`), so this always returns
/// [`ErrorKind::Unsupported`].
pub fn enable_debug_privilege() -> Result<(), Error> {
    Err(Error::new(
        ErrorKind::Unsupported,
        None,
        "debug privileges are a Windows concept; use ptrace permissions on Linux",
    ))
}

fn process_exited(pid: u32) -> Error {
    Error::new(
        ErrorKind::ProcessExited,
        None,
        format!("process {pid} exited or its PID was reused"),
    )
}

fn open_proc_file(dir: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: `dir` is an open directory descriptor, `name` is a valid
    // NUL-terminated path relative to it, and `flags` contains no O_CREAT or
    // other flag requiring a mode argument. The returned descriptor is owned
    // by the File constructed below.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` is a fresh, valid descriptor and ownership is
        // transferred exactly once to the returned File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn read_proc_file(dir: &File, name: &CStr) -> Result<Vec<u8>, Error> {
    let mut file = open_proc_file(dir, name, libc::O_RDONLY).map_err(io_error)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(io_error)?;
    Ok(data)
}

fn pread(file: &File, buffer: &mut [u8], offset: i64) -> io::Result<usize> {
    loop {
        // SAFETY: the descriptor is open, `buffer` is valid for writes of
        // `buffer.len()` bytes, and `offset` was checked to be non-negative.
        let result = unsafe {
            libc::pread64(
                file.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                offset,
            )
        };
        if result >= 0 {
            // A non-negative ssize_t is always representable as usize.
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn pwrite(file: &File, buffer: &[u8], offset: i64) -> io::Result<usize> {
    loop {
        // SAFETY: the descriptor is open, `buffer` is valid for reads of
        // `buffer.len()` bytes, and `offset` was checked to be non-negative.
        let result = unsafe {
            libc::pwrite64(
                file.as_raw_fd(),
                buffer.as_ptr().cast(),
                buffer.len(),
                offset,
            )
        };
        if result >= 0 {
            // A non-negative ssize_t is always representable as usize.
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn procfs_offset(address: u64, len: usize) -> Result<i64, Error> {
    let len = u64::try_from(len).map_err(|_| invalid_range(address))?;
    address
        .checked_add(len)
        .filter(|end| *end <= i64::MAX as u64)
        .ok_or_else(|| invalid_range(address))?;
    i64::try_from(address).map_err(|_| invalid_range(address))
}

fn invalid_range(address: u64) -> Error {
    Error::new(
        ErrorKind::InvalidAddress,
        None,
        format!("address range starting at {address:#x} cannot be represented by /proc/<pid>/mem"),
    )
}

fn open_verified_pidfd(pid: u32, proc_dir: &File, start_time: u64) -> Option<File> {
    let pidfd = open_pidfd(pid)?;
    match read_stat(proc_dir, pid) {
        Ok(stat) if stat.start_time == start_time && !is_dead_state(stat.state) => Some(pidfd),
        _ => None,
    }
}

fn open_pidfd(pid: u32) -> Option<File> {
    // SAFETY: pidfd_open takes a PID and flags and returns a new file
    // descriptor or -1. The descriptor is adopted by `File` only after the
    // success check.
    let raw =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0 as libc::c_long) };
    let fd = libc::c_int::try_from(raw).ok()?;
    if fd < 0 {
        return None;
    }
    // SAFETY: the kernel just returned this fresh descriptor and ownership is
    // transferred to the `File`.
    Some(unsafe { File::from_raw_fd(fd) })
}

fn poll_pidfd(fd: RawFd, timeout: Option<Duration>) -> Result<bool, Error> {
    let started = Instant::now();
    loop {
        let expired = timeout.is_some_and(|limit| started.elapsed() >= limit);
        let wait_ms = match timeout {
            None => -1,
            Some(_) if expired => 0,
            Some(limit) => poll_timeout_millis(limit.saturating_sub(started.elapsed())),
        };
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` points to one initialized pollfd and remains
        // valid for the call. The fd is owned by the process handle.
        let result = unsafe { libc::poll(&mut descriptor, 1, wait_ms) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io_error(error));
        }
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io_error(io::Error::from_raw_os_error(libc::EBADF)));
            }
            if descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                return Ok(true);
            }
            if descriptor.revents & libc::POLLERR != 0 {
                return Err(Error::new(
                    ErrorKind::Other,
                    None,
                    "pidfd poll reported POLLERR",
                ));
            }
            continue;
        }
        if expired {
            return Ok(false);
        }
    }
}

fn poll_timeout_millis(remaining: Duration) -> libc::c_int {
    let millis = remaining
        .as_millis()
        .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
    millis.min(libc::c_int::MAX as u128) as libc::c_int
}

/// Classifies an error from a `/proc/<pid>/mem` transfer.
///
/// The kernel reports an unmapped address as `EIO`, which is the most common
/// failure in this library. Map it to `InvalidAddress` (keeping errno) so it is
/// distinguishable from unrelated I/O failures and matches Windows.
fn mem_io_error(error: io::Error) -> Error {
    if error.raw_os_error() == Some(libc::EIO) {
        Error::new(
            ErrorKind::InvalidAddress,
            Some(libc::EIO),
            io_message(libc::EIO),
        )
    } else {
        io_error(error)
    }
}

fn io_error(error: io::Error) -> Error {
    let raw_code = error.raw_os_error();
    let kind = match raw_code {
        Some(libc::ENOENT) => ErrorKind::NotFound,
        Some(libc::ESRCH) => ErrorKind::ProcessExited,
        Some(libc::EACCES | libc::EPERM) => ErrorKind::PermissionDenied,
        Some(libc::EINVAL) => ErrorKind::InvalidAddress,
        Some(libc::ENOSYS) => ErrorKind::Unsupported,
        _ => ErrorKind::Other,
    };
    let message = raw_code.map_or_else(|| error.to_string(), io_message);
    Error::new(kind, raw_code, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stat {
    state: u8,
    start_time: u64,
}

fn read_stat(dir: &File, pid: u32) -> Result<Stat, Error> {
    // `/proc/<pid>/stat` is a few hundred bytes. Read it into a fixed buffer so
    // a liveness poll does not allocate on every tick.
    let mut file = open_proc_file(dir, STAT, libc::O_RDONLY).map_err(io_error)?;
    let mut buffer = [0u8; 4096];
    let mut length = 0usize;
    loop {
        match file.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(read) => {
                length += read;
                if length == buffer.len() {
                    return Err(Error::malformed(format!(
                        "/proc/{pid}/stat is larger than {} bytes",
                        buffer.len()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    parse_stat(&buffer[..length], pid)
}

fn parse_stat(data: &[u8], pid: u32) -> Result<Stat, Error> {
    let malformed =
        |reason: &str| Error::malformed(format!("/proc/{pid}/stat is malformed: {reason}"));

    let close = data
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(|| malformed("missing command terminator"))?;
    let tail = data
        .get(close + 1..)
        .ok_or_else(|| malformed("truncated"))?;
    let mut fields = tail
        .split(|byte: &u8| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let state = fields
        .next()
        .and_then(|field| field.first().copied())
        .ok_or_else(|| malformed("missing process state"))?;
    let start_time = fields
        .nth(18)
        .ok_or_else(|| malformed("missing start time"))?;
    let start_time = std::str::from_utf8(start_time)
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(|| malformed("invalid start time"))?;

    Ok(Stat { state, start_time })
}

fn is_dead_state(state: u8) -> bool {
    matches!(state, b'Z' | b'X' | b'x')
}

/// Identity of a mapped file, taken from the `dev` and `inode` columns of
/// `/proc/<pid>/maps`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FileId {
    dev: u64,
    inode: u64,
}

/// One parsed `/proc/<pid>/maps` line.
#[derive(Debug)]
struct MapsEntry {
    region: RawRegion,
    file_id: Option<FileId>,
}

fn parse_maps(data: &[u8], pid: u32) -> Result<Vec<MapsEntry>, Error> {
    let mut entries = Vec::new();
    for (index, line) in data.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let entry = parse_maps_line(line).map_err(|reason| {
            Error::malformed(format!(
                "/proc/{pid}/maps line {} is malformed: {reason}",
                index + 1
            ))
        })?;
        entries.push(entry);
    }
    entries.sort_by_key(|entry| entry.region.base);
    Ok(entries)
}

fn parse_maps_line(line: &[u8]) -> Result<MapsEntry, String> {
    let mut position = 0;
    let range = next_field(line, &mut position).ok_or("missing address range")?;
    let permissions = next_field(line, &mut position).ok_or("missing permissions")?;
    let _offset = next_field(line, &mut position).ok_or("missing file offset")?;
    let device = next_field(line, &mut position).ok_or("missing device")?;
    let inode = next_field(line, &mut position).ok_or("missing inode")?;

    let (base, end) = parse_range(range)?;
    let protection = parse_permissions(permissions)?;

    let path = {
        // The kernel pads the pathname column with spaces after the inode.
        // Skip the whole padding run; real paths are absolute and start with
        // '/', and special mappings start with '['.
        while position < line.len() && line[position].is_ascii_whitespace() {
            position += 1;
        }
        let bytes = line.get(position..).unwrap_or_default();
        // The kernel appends this marker for deleted mappings. A real file name
        // ending in the same text is indistinguishable; accept the ambiguity.
        let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
        if bytes.is_empty() || bytes.first() == Some(&b'[') {
            None
        } else {
            Some(PathBuf::from(OsString::from_vec(bytes.to_vec())))
        }
    };
    let kind = if path.is_some() {
        RegionKind::Mapped
    } else {
        RegionKind::Private
    };
    let file_id = match &path {
        Some(_) => Some(parse_file_id(device, inode)?),
        None => None,
    };

    Ok(MapsEntry {
        region: RawRegion {
            base,
            size: end - base,
            protection,
            kind,
            path,
        },
        file_id,
    })
}

fn parse_file_id(device: &[u8], inode: &[u8]) -> Result<FileId, String> {
    let device = std::str::from_utf8(device).map_err(|_| "device is not ASCII")?;
    let (major, minor) = device
        .split_once(':')
        .ok_or("device does not contain ':'")?;
    let major =
        u32::from_str_radix(major, 16).map_err(|_| format!("invalid device major {major:?}"))?;
    let minor =
        u32::from_str_radix(minor, 16).map_err(|_| format!("invalid device minor {minor:?}"))?;
    let inode = std::str::from_utf8(inode)
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or("invalid inode")?;
    Ok(FileId {
        dev: libc::makedev(major, minor) as u64,
        inode,
    })
}

fn next_field<'a>(line: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    while *position < line.len() && line[*position] == b' ' {
        *position += 1;
    }
    if *position >= line.len() {
        return None;
    }
    let start = *position;
    while *position < line.len() && line[*position] != b' ' {
        *position += 1;
    }
    Some(&line[start..*position])
}

fn parse_range(token: &[u8]) -> Result<(u64, u64), String> {
    let dash = token
        .iter()
        .position(|byte| *byte == b'-')
        .ok_or("address range lacks '-'")?;
    let (start, rest) = token.split_at(dash);
    let end = rest.get(1..).ok_or("address range lacks end")?;
    let start = parse_hex(start)?;
    let end = parse_hex(end)?;
    if end <= start {
        return Err("address range end is not greater than its start".to_owned());
    }
    Ok((start, end))
}

fn parse_hex(bytes: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "address is not ASCII")?;
    u64::from_str_radix(text, 16).map_err(|_| format!("invalid hexadecimal number {text:?}"))
}

fn parse_permissions(permissions: &[u8]) -> Result<Protection, String> {
    if permissions.len() != 4 {
        return Err("permissions must contain four characters".to_owned());
    }
    if !matches!(permissions[3], b'p' | b's') {
        return Err("mapping must be private or shared".to_owned());
    }
    Ok(permission(permissions[0], b'r', Protection::READ)?
        | permission(permissions[1], b'w', Protection::WRITE)?
        | permission(permissions[2], b'x', Protection::EXECUTE)?)
}

fn permission(actual: u8, expected: u8, flag: Protection) -> Result<Protection, String> {
    match actual {
        byte if byte == expected => Ok(flag),
        b'-' => Ok(Protection::empty()),
        other => Err(format!("invalid permission byte {:?}", char::from(other))),
    }
}

fn modules_from_entries(entries: &[MapsEntry]) -> Vec<RawModule> {
    let executable_files: HashSet<FileId> = entries
        .iter()
        .filter(|entry| entry.region.protection.is_executable())
        .filter_map(|entry| entry.file_id)
        .collect();

    let mut spans: HashMap<FileId, (u64, u64, &Path)> = HashMap::new();
    for entry in entries {
        let Some(file_id) = entry.file_id else {
            continue;
        };
        if !executable_files.contains(&file_id) {
            continue;
        }
        let Some(path) = entry.region.path.as_deref() else {
            continue;
        };
        let end = entry.region.base.saturating_add(entry.region.size);
        match spans.entry(file_id) {
            std::collections::hash_map::Entry::Vacant(vacant) => {
                vacant.insert((entry.region.base, end, path));
            }
            std::collections::hash_map::Entry::Occupied(mut occupied) => {
                let span = occupied.get_mut();
                if entry.region.base < span.0 {
                    span.0 = entry.region.base;
                    span.2 = path;
                }
                span.1 = span.1.max(end);
            }
        }
    }

    let mut modules: Vec<RawModule> = spans
        .into_iter()
        .filter_map(|(_, (base, end, path))| {
            let size = end.checked_sub(base)?;
            if size == 0 {
                return None;
            }
            let name = path.file_name().map_or_else(
                || path.to_string_lossy().into_owned(),
                |name| name.to_string_lossy().into_owned(),
            );
            Some(RawModule {
                name,
                path: path.to_path_buf(),
                base,
                size,
            })
        })
        .collect();
    modules.sort_by(|left, right| {
        left.base
            .cmp(&right.base)
            .then_with(|| left.name.cmp(&right.name))
    });
    modules
}

/// Builds the target-namespace path of a module file, relative to an open
/// `/proc/<pid>` directory descriptor.
///
/// The path must be absolute and must not contain a parent-directory component;
/// it is prefixed with `root/` so that `openat` follows the target's root link.
/// Non-UTF-8 path bytes are preserved.
fn target_relative_module_path(path: &Path) -> Result<CString, Error> {
    let safe = path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir));
    if !safe {
        return Err(Error::malformed(format!(
            "module path {} is not a safe absolute path",
            path.display()
        )));
    }
    let relative = path
        .strip_prefix("/")
        .map_err(|_| Error::malformed(format!("module path {} is not absolute", path.display())))?;
    let mut bytes = b"root/".to_vec();
    bytes.extend_from_slice(relative.as_os_str().as_bytes());
    CString::new(bytes).map_err(|_| {
        Error::malformed(format!(
            "module path {} contains a NUL byte",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_line(state: u8, start_time: u64) -> Vec<u8> {
        let mut line = format!("4242 (memdiver fixture) {}", char::from(state));
        for field in 4..22 {
            line.push(' ');
            line.push_str(&field.to_string());
        }
        line.push(' ');
        line.push_str(&start_time.to_string());
        line.into_bytes()
    }

    #[test]
    fn parses_stat_and_start_time() {
        let stat = parse_stat(&stat_line(b'S', 987_654), 4242).expect("valid stat");
        assert_eq!(stat.state, b'S');
        assert_eq!(stat.start_time, 987_654);
    }

    #[test]
    fn parses_stat_with_comm_containing_spaces_and_parentheses() {
        let mut line = b"77 (a) tricky ) process) R".to_vec();
        for field in 4..=21 {
            line.push(b' ');
            line.extend_from_slice(field.to_string().as_bytes());
        }
        line.extend_from_slice(b" 1234");
        let stat = parse_stat(&line, 77).expect("valid stat");
        assert_eq!(stat.state, b'R');
        assert_eq!(stat.start_time, 1234);
    }

    #[test]
    fn parses_zombie_state() {
        let stat = parse_stat(&stat_line(b'Z', 1), 4242).expect("valid stat");
        assert!(is_dead_state(stat.state));
        assert!(!is_dead_state(b'S'));
        assert!(!is_dead_state(b'R'));
    }

    #[test]
    fn rejects_malformed_stat() {
        assert_eq!(
            parse_stat(b"42 no closing parenthesis", 42)
                .expect_err("must fail")
                .kind(),
            ErrorKind::MalformedData
        );
        assert_eq!(
            parse_stat(b"42 (comm) S 1 2", 42)
                .expect_err("must fail")
                .kind(),
            ErrorKind::MalformedData
        );

        let mut line = stat_line(b'S', 1);
        let last_space = line.iter().rposition(|byte| *byte == b' ').expect("space");
        line.truncate(last_space);
        line.extend_from_slice(b" not-a-number");
        assert_eq!(
            parse_stat(&line, 42).expect_err("must fail").kind(),
            ErrorKind::MalformedData
        );
    }

    fn maps_line(prefix: &str, path: &str) -> Vec<u8> {
        format!("{prefix} {path}").into_bytes()
    }

    #[test]
    fn parses_regular_maps_entry() {
        let line = b"7f0000000000-7f0000001000 r-xp 00000000 08:01 1234 /usr/lib/libfoo.so.1";
        let entry = parse_maps_line(line).expect("valid maps line");
        let region = &entry.region;
        assert_eq!(region.base, 0x7f00_0000_0000);
        assert_eq!(region.size, 0x1000);
        assert_eq!(region.protection, Protection::READ | Protection::EXECUTE);
        assert_eq!(region.kind, RegionKind::Mapped);
        assert_eq!(
            region.path.as_deref(),
            Some(Path::new("/usr/lib/libfoo.so.1"))
        );
        assert_eq!(
            entry.file_id,
            Some(FileId {
                dev: libc::makedev(8, 1) as u64,
                inode: 1234
            })
        );
    }

    #[test]
    fn parses_shared_and_write_only_permissions() {
        let shared = parse_maps_line(b"1000-2000 rw-s 00000000 00:00 0 /tmp/shared")
            .expect("valid maps line");
        assert_eq!(
            shared.region.protection,
            Protection::READ | Protection::WRITE
        );

        let write_only =
            parse_maps_line(b"2000-3000 -w-p 00000000 00:00 0").expect("valid maps line");
        assert_eq!(write_only.region.protection, Protection::WRITE);
        assert_eq!(write_only.region.path, None);
        assert_eq!(write_only.region.kind, RegionKind::Private);
        assert_eq!(write_only.file_id, None);
    }

    #[test]
    fn parses_paths_with_spaces_and_deleted_suffix() {
        let line = maps_line(
            "1000-2000 rw-p 00000000 00:00 7",
            "/tmp/name with spaces (deleted)",
        );
        let entry = parse_maps_line(&line).expect("valid maps line");
        assert_eq!(
            entry.region.path.as_deref(),
            Some(Path::new("/tmp/name with spaces"))
        );
    }

    #[test]
    fn parses_pathname_column_padding() {
        let line = b"1000-2000 r-xp 00000000 00:00 1234                    /usr/lib/libfoo.so.1";
        let entry = parse_maps_line(line).expect("valid padded maps line");
        assert_eq!(
            entry.region.path.as_deref(),
            Some(Path::new("/usr/lib/libfoo.so.1"))
        );

        let heap =
            parse_maps_line(b"2000-3000 rw-p 00000000 00:00 0                          [heap]")
                .expect("valid padded heap line");
        assert_eq!(heap.region.path, None);
        assert_eq!(heap.region.kind, RegionKind::Private);
    }

    #[test]
    fn preserves_non_utf8_mapping_paths() {
        use std::os::unix::ffi::OsStrExt;

        let line = b"1000-2000 r-xp 00000000 00:00 9 /tmp/name-\xff";
        let entry = parse_maps_line(line).expect("valid maps line");
        let path = entry.region.path.expect("file-backed mapping has a path");
        assert_eq!(path.as_os_str().as_bytes(), b"/tmp/name-\xff");
    }

    #[test]
    fn special_mappings_have_no_path() {
        let heap =
            parse_maps_line(b"5555-6666 rw-p 00000000 00:00 0 [heap]").expect("valid maps line");
        assert_eq!(heap.region.path, None);
        assert_eq!(heap.region.kind, RegionKind::Private);
    }

    #[test]
    fn rejects_malformed_maps_lines() {
        let invalid = [
            b"1000-2000".as_slice(),
            b"1000-2000 r-xp".as_slice(),
            b"zzzz-2000 r-xp 0 0 0".as_slice(),
            b"1000-1000 r-xp 0 0 0".as_slice(),
            b"1000-2000 r-xq 0 0 0".as_slice(),
            b"1000-2000 r-x 0 0 0".as_slice(),
            b"1000-2000 r-xp 0 0".as_slice(),
        ];
        for line in invalid {
            assert!(
                parse_maps_line(line).is_err(),
                "line {:?} should be rejected",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn parse_maps_sorts_and_numbers_lines() {
        let data = b"2000-3000 rw-p 0 00:00 0 [heap]\n1000-2000 r-xp 0 00:00 0 /bin/app\n";
        let entries = parse_maps(data, 7).expect("valid maps");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].region.base, 0x1000);
        assert_eq!(entries[1].region.base, 0x2000);

        let error = parse_maps(b"1000-2000 rw-p 0 00:00 0\nbad\n", 7).expect_err("must fail");
        assert_eq!(error.kind(), ErrorKind::MalformedData);
        assert!(error.message().contains("line 2"));
    }

    fn raw_entry(
        base: u64,
        size: u64,
        protection: Protection,
        path: Option<&str>,
        inode: Option<u64>,
    ) -> MapsEntry {
        MapsEntry {
            region: RawRegion {
                base,
                size,
                protection,
                kind: if path.is_some() {
                    RegionKind::Mapped
                } else {
                    RegionKind::Private
                },
                path: path.map(PathBuf::from),
            },
            file_id: inode.map(|inode| FileId { dev: 1, inode }),
        }
    }

    #[test]
    fn modules_merge_executable_mappings_only() {
        let entries = vec![
            raw_entry(
                0x1000,
                0x1000,
                Protection::READ,
                Some("/lib/libx.so.1"),
                Some(10),
            ),
            raw_entry(
                0x2000,
                0x1000,
                Protection::READ | Protection::EXECUTE,
                Some("/lib/libx.so.1"),
                Some(10),
            ),
            raw_entry(
                0x3000,
                0x1000,
                Protection::READ,
                Some("/data/file"),
                Some(11),
            ),
            raw_entry(
                0x4000,
                0x1000,
                Protection::READ | Protection::WRITE,
                None,
                None,
            ),
            raw_entry(
                0x5000,
                0x1000,
                Protection::READ | Protection::EXECUTE,
                Some("/usr/bin/app"),
                Some(12),
            ),
        ];
        let modules = modules_from_entries(&entries);
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "libx.so.1");
        assert_eq!(modules[0].base, 0x1000);
        assert_eq!(modules[0].size, 0x2000);
        assert_eq!(modules[1].name, "app");
        assert_eq!(modules[1].base, 0x5000);
        assert_eq!(modules[1].size, 0x1000);
    }

    #[test]
    fn modules_do_not_merge_distinct_files_with_one_path() {
        let entries = vec![
            raw_entry(
                0x1000,
                0x1000,
                Protection::READ | Protection::EXECUTE,
                Some("/opt/app/libfoo.so"),
                Some(20),
            ),
            raw_entry(
                0x3000,
                0x1000,
                Protection::READ | Protection::EXECUTE,
                Some("/opt/app/libfoo.so"),
                Some(21),
            ),
        ];
        let modules = modules_from_entries(&entries);
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].base, 0x1000);
        assert_eq!(modules[1].base, 0x3000);
    }

    #[test]
    fn modules_ignore_anonymous_executable_mappings() {
        let entries = vec![raw_entry(
            0x1000,
            0x1000,
            Protection::READ | Protection::EXECUTE,
            None,
            None,
        )];
        assert!(modules_from_entries(&entries).is_empty());
    }

    #[test]
    fn builds_target_relative_paths_and_rejects_escapes() {
        assert_eq!(
            target_relative_module_path(Path::new("/usr/lib/libfoo.so"))
                .expect("valid path")
                .to_bytes(),
            b"root/usr/lib/libfoo.so"
        );
        assert!(target_relative_module_path(Path::new("relative/libfoo.so")).is_err());
        assert!(target_relative_module_path(Path::new("/usr/../etc/passwd")).is_err());
        let non_utf8 = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/name-\xff"));
        assert_eq!(
            target_relative_module_path(non_utf8)
                .expect("non-UTF-8 path")
                .to_bytes(),
            b"root/tmp/name-\xff"
        );
    }

    #[test]
    fn rejects_procfs_offsets_beyond_i64() {
        assert!(procfs_offset(i64::MAX as u64, 1).is_err());
        assert!(procfs_offset(0, 16).is_ok());
        assert_eq!(
            procfs_offset(u64::MAX, 1).expect_err("must fail").kind(),
            ErrorKind::InvalidAddress
        );
    }

    #[test]
    fn poll_timeout_rounds_up_and_caps() {
        assert_eq!(poll_timeout_millis(Duration::ZERO), 0);
        assert_eq!(poll_timeout_millis(Duration::from_nanos(1)), 1);
        assert_eq!(poll_timeout_millis(Duration::from_millis(1)), 1);
        assert_eq!(poll_timeout_millis(Duration::from_micros(1_500)), 2);
        assert_eq!(poll_timeout_millis(Duration::from_millis(1_500)), 1_500);
        assert_eq!(poll_timeout_millis(Duration::MAX), libc::c_int::MAX);
    }

    #[test]
    fn poll_helper_wakes_and_times_out() {
        use std::io::Write;

        let mut fds = [0; 2];
        // SAFETY: `fds` points to two writable integers.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: the pipe returned two fresh descriptors, each owned by one File.
        let reader = unsafe { File::from_raw_fd(fds[0]) };
        // SAFETY: as above.
        let mut writer = unsafe { File::from_raw_fd(fds[1]) };

        assert!(!poll_pidfd(reader.as_raw_fd(), Some(Duration::ZERO)).expect("immediate poll"));
        assert!(
            !poll_pidfd(reader.as_raw_fd(), Some(Duration::from_millis(5))).expect("timeout poll")
        );
        writer.write_all(b"x").expect("write pipe");
        assert!(poll_pidfd(reader.as_raw_fd(), Some(Duration::from_secs(1))).expect("wake poll"));

        // Dropping the writer leaves only POLLHUP on the read end.
        drop(writer);
        assert!(poll_pidfd(reader.as_raw_fd(), Some(Duration::from_secs(1))).expect("hangup poll"));
    }

    #[test]
    fn start_time_mismatch_is_reported_as_exited() {
        let handle = ProcessHandle::open(std::process::id()).expect("open self");
        let bogus = ProcessHandle {
            start_time: handle.start_time.wrapping_add(1),
            ..handle
        };
        assert!(!bogus.is_alive());
        assert_eq!(
            bogus
                .ensure_same_process()
                .expect_err("a reused PID must be rejected")
                .kind(),
            ErrorKind::ProcessExited
        );
        assert!(bogus.regions().is_err());
    }

    #[test]
    fn process_info_reports_identity() {
        let info = process_info(std::process::id()).expect("self is listed");
        assert_eq!(info.pid, std::process::id());
        assert!(info.start_time.is_some(), "self must expose its start time");
    }

    #[test]
    fn polling_fallback_observes_exit() {
        let mut child = std::process::Command::new("sleep")
            .arg("0.05")
            .spawn()
            .expect("spawn sleep");
        let handle = ProcessHandle::open(child.id()).expect("open child");
        assert!(
            handle
                .wait_for_exit_polling(Some(Duration::from_secs(2)))
                .expect("polling wait"),
            "the polling fallback must observe the child's exit"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn polling_fallback_respects_timeout() {
        let handle = ProcessHandle::open(std::process::id()).expect("open self");
        assert!(
            !handle
                .wait_for_exit_polling(Some(Duration::ZERO))
                .expect("fallback poll")
        );
    }

    #[test]
    fn classifies_io_errors() {
        assert_eq!(
            io_error(io::Error::from_raw_os_error(libc::ENOENT)).kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            io_error(io::Error::from_raw_os_error(libc::EACCES)).kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            io_error(io::Error::from_raw_os_error(libc::ESRCH)).kind(),
            ErrorKind::ProcessExited
        );
        assert_eq!(
            io_error(io::Error::from_raw_os_error(libc::EINVAL)).kind(),
            ErrorKind::InvalidAddress
        );
        assert_eq!(
            mem_io_error(io::Error::from_raw_os_error(libc::EIO)).kind(),
            ErrorKind::InvalidAddress
        );
        assert_eq!(
            mem_io_error(io::Error::from_raw_os_error(libc::EACCES)).kind(),
            ErrorKind::PermissionDenied
        );
    }
}

//! The safe process handle.

use std::fmt;
use std::mem::size_of;
use std::sync::{Mutex, MutexGuard, PoisonError};

use bytemuck::Pod;
use memdiver_sys::ErrorKind as OsErrorKind;
use memdiver_sys::{
    CodeWriteError, CodeWriteFailure, ProcessHandle, RestoreFailure,
    processes as platform_processes,
};

use crate::error::open_error;
use crate::process_info::name_matches;
use crate::{
    Address, Error, Module, ModuleMap, ProcessInfo, Protection, Region, RegionMap, Result,
};

/// Number of attempts for an open-by-name operation whose candidate can be
/// replaced between enumeration and verification.
const OPEN_BY_NAME_ATTEMPTS: usize = 3;

/// Requested access level for a process handle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProcessAccess {
    /// Read and write access, including the ability to change protections.
    #[default]
    ReadWrite,
    /// Read-only access. Writes and protection changes are rejected before any
    /// operating-system call.
    ReadOnly,
}

impl ProcessAccess {
    /// Returns `true` when this access level permits writes.
    #[must_use]
    pub fn is_writable(self) -> bool {
        matches!(self, Self::ReadWrite)
    }
}

/// A handle to another process's memory.
///
/// Opening a process pins the underlying operating-system handle. On Linux the
/// `/proc/<pid>/mem` descriptor refers to the memory map that existed when the
/// handle was opened; on Windows the kernel `HANDLE` pins the process object.
/// A Linux target that calls `execve` keeps its PID and start time but installs
/// a new address space; reads then return [`Error::AddressSpaceReplaced`] and
/// the handle must be reopened.
/// Closing or dropping the `Process` never terminates or otherwise modifies the
/// target's execution state.
///
/// A handle can be opened read-write ([`Process::open`]) or read-only
/// ([`Process::open_readonly`]). Use [`Process::list`],
/// [`Process::find_by_name`], and [`Process::open_by_name`] for PID discovery.
///
/// `Process` is [`Send`] and [`Sync`]: reads and writes use positional I/O on
/// Linux and thread-safe Win32 handle operations on Windows. Concurrent writes
/// to overlapping ranges are forwarded to the operating system without
/// additional ordering. Protection-changing operations (`write_code` and
/// `protect`) are serialized per handle; separate handles to the same process
/// are not coordinated, so callers must not change protection for the same page
/// concurrently through different handles.
///
/// # Security and safety
///
/// Access is mediated by the operating system. On Linux the caller needs ptrace
/// access (same UID and a permissive `ptrace_scope`, or `CAP_SYS_PTRACE`); on
/// Windows the caller needs the corresponding `OpenProcess` rights.
///
/// Reading arbitrary memory as raw bytes is memory-safe in the Rust sense.
/// Writing to a live process can corrupt its state and crash it; that danger is
/// inherent in the operation and is documented rather than hidden behind
/// `unsafe`.
pub struct Process {
    pub(crate) pid: u32,
    access: ProcessAccess,
    pub(crate) inner: ProcessHandle,
    /// Serializes protection-changing operations on this handle. Without it,
    /// two threads can record and restore one page's protection in the wrong
    /// order and leave the page writable and executable.
    protection_lock: Mutex<()>,
}

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process")
            .field("pid", &self.pid)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

impl Process {
    /// Opens the process with the given PID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProcessNotFound`] when the process does not exist,
    /// [`Error::AccessDenied`] when the operating system denies access, and
    /// [`Error::Open`] for other failures.
    pub fn open(pid: u32) -> Result<Self> {
        Self::open_with(pid, ProcessAccess::ReadWrite)
    }

    /// Opens the process with the given PID using an explicit access level.
    ///
    /// A [`ProcessAccess::ReadOnly`] handle requests only the rights needed to
    /// inspect the target. Write and protection operations return
    /// [`Error::ReadOnly`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProcessNotFound`] when the process does not exist,
    /// [`Error::AccessDenied`] when the operating system denies the requested
    /// access, and [`Error::Open`] for other failures.
    pub fn open_with(pid: u32, access: ProcessAccess) -> Result<Self> {
        let inner = ProcessHandle::open_with(pid, access.is_writable())
            .map_err(|source| open_error(pid, source))?;
        Ok(Self {
            pid,
            access,
            inner,
            protection_lock: Mutex::new(()),
        })
    }

    /// Opens a read-only handle to the process with the given PID.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::open_with`].
    pub fn open_readonly(pid: u32) -> Result<Self> {
        Self::open_with(pid, ProcessAccess::ReadOnly)
    }

    /// Enumerates the processes visible to the caller.
    ///
    /// The result is sorted by PID. Individual processes that exit or cannot be
    /// inspected during enumeration are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProcessList`] when the operating system cannot provide
    /// a process snapshot.
    pub fn list() -> Result<Vec<ProcessInfo>> {
        let processes = platform_processes().map_err(|source| Error::ProcessList { source })?;
        Ok(processes.into_iter().map(ProcessInfo::from_raw).collect())
    }

    /// Finds processes whose name matches `name`.
    ///
    /// Matching is case-sensitive on Linux and ASCII case-insensitive on
    /// Windows. The executable file name is considered when available.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProcessList`] when the process list cannot be read.
    pub fn find_by_name(name: &str) -> Result<Vec<ProcessInfo>> {
        Ok(Self::list()?
            .into_iter()
            .filter(|process| process.matches_name(name))
            .collect())
    }

    /// Opens the unique process matching `name`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProcessNameNotFound`] when nothing matches,
    /// [`Error::AmbiguousProcessName`] when more than one process matches, and
    /// the same open errors as [`Process::open`] otherwise.
    pub fn open_by_name(name: &str) -> Result<Self> {
        Self::open_by_name_with(name, ProcessAccess::ReadWrite)
    }

    /// Opens the unique process matching `name` with an explicit access level.
    ///
    /// The opened process is verified against its name after opening; a process
    /// that exits or is replaced during the operation is retried a bounded
    /// number of times before [`Error::ProcessChanged`] is returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProcessNameNotFound`] when nothing matches,
    /// [`Error::AmbiguousProcessName`] when more than one process matches,
    /// [`Error::ProcessChanged`] when the matching process keeps changing, and
    /// the same open errors as [`Process::open_with`] otherwise.
    pub fn open_by_name_with(name: &str, access: ProcessAccess) -> Result<Self> {
        for _ in 0..OPEN_BY_NAME_ATTEMPTS {
            let mut candidates = Self::find_by_name(name)?;
            match candidates.len() {
                0 => {
                    return Err(Error::ProcessNameNotFound {
                        name: name.to_owned(),
                    });
                }
                1 => {
                    let candidate = candidates.pop().expect("one candidate");
                    let process = match Self::open_with(candidate.pid(), access) {
                        Ok(process) => process,
                        Err(Error::ProcessNotFound { .. }) => continue,
                        Err(Error::Open { source, .. })
                            if matches!(source.kind(), OsErrorKind::ProcessExited) =>
                        {
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    if !verified_name(process.name()?.as_deref(), name) {
                        continue;
                    }
                    return Ok(process);
                }
                _ => {
                    return Err(Error::AmbiguousProcessName {
                        name: name.to_owned(),
                        candidates,
                    });
                }
            }
        }
        Err(Error::ProcessChanged {
            name: name.to_owned(),
        })
    }

    /// Returns the PID of the target process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the access level this handle was opened with.
    #[must_use]
    pub fn access(&self) -> ProcessAccess {
        self.access
    }

    /// Returns `true` when this handle can write to the target.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.access.is_writable()
    }

    /// Returns the target's executable path when the operating system exposes
    /// it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Query`] for unexpected metadata failures.
    pub fn exe_path(&self) -> Result<Option<std::path::PathBuf>> {
        self.inner.exe_path().map_err(|source| Error::Query {
            pid: self.pid,
            what: "executable path",
            source,
        })
    }

    /// Returns the target's executable file name when available.
    ///
    /// Names that are not valid Unicode are converted lossily; use
    /// [`Process::exe_path`] when the exact path bytes matter.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::exe_path`].
    pub fn name(&self) -> Result<Option<String>> {
        Ok(self.exe_path()?.and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        }))
    }

    /// Returns whether the target process is still running.
    ///
    /// On Linux a zombie is reported as not alive and PID reuse is detected
    /// through the process start time captured when the handle was opened. On
    /// Windows this waits on the process handle with a zero timeout. A failure
    /// to query liveness is reported as `false`.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    /// Reads `buffer.len()` bytes from `address` into `buffer`.
    ///
    /// A zero-length read is a no-op and does not access the target.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error wrapped in [`Error::Read`] when the
    /// read fails, [`Error::AddressRange`] when the range overflows,
    /// [`Error::AddressSpaceReplaced`] when the target replaced its address
    /// space after opening, or [`Error::PartialRead`] when the operating system
    /// transfers fewer bytes than requested. On Windows a failed
    /// `ReadProcessMemory` that copied a prefix is reported as
    /// [`Error::PartialRead`] with the copied count. On any error the contents
    /// of `buffer` are unspecified; inspect the `transferred` count in a
    /// partial-read error.
    pub fn read(&self, address: Address, buffer: &mut [u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        validate_range(self.pid, address, buffer.len())?;
        let transferred = self
            .inner
            .read(address.get(), buffer)
            .map_err(|source| self.read_error(address, buffer.len(), source))?;
        ensure_complete_read(self.pid, address, buffer.len(), transferred)
    }

    /// Reads `len` bytes from `address` into a new buffer.
    ///
    /// A zero-length read returns an empty vector without accessing the target.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::read`], plus [`Error::Allocation`]
    /// when the output buffer cannot be allocated. On [`Error::PartialRead`]
    /// the partially filled vector is not returned; use [`Process::read`] with
    /// a caller-provided buffer when the transferred prefix is needed.
    pub fn read_bytes(&self, address: Address, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        validate_range(self.pid, address, len)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(len)
            .map_err(|source| Error::Allocation { len, source })?;
        buffer.resize(len, 0);
        self.read(address, &mut buffer)?;
        Ok(buffer)
    }

    /// Writes `buffer` to `address` in the target process.
    ///
    /// A zero-length write is a no-op and does not access the target. On
    /// Windows, writing to an executable, non-writable code page fails; use
    /// [`Process::write_code`] for reversible code patches, which temporarily
    /// raises page protection and restores it.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error wrapped in [`Error::Write`] when the
    /// write fails, [`Error::AddressRange`] when the range overflows,
    /// [`Error::AddressSpaceReplaced`] when the target replaced its address
    /// space after opening, or [`Error::PartialWrite`] when the operating
    /// system transfers fewer bytes than requested. On Windows a failed
    /// `WriteProcessMemory` that copied a prefix is reported as
    /// [`Error::PartialWrite`] with the copied count. A failed or partial write
    /// may already have modified the target.
    pub fn write(&self, address: Address, buffer: &[u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        if !self.is_writable() {
            return Err(Error::ReadOnly {
                pid: self.pid,
                operation: "Process::write",
            });
        }
        validate_range(self.pid, address, buffer.len())?;
        let transferred = self
            .inner
            .write(address.get(), buffer)
            .map_err(|source| self.write_error(address, buffer.len(), source))?;
        ensure_complete_write(self.pid, address, buffer.len(), transferred)
    }

    /// Writes `buffer` to `address` as a scoped code write.
    ///
    /// This is the supported helper for reversible code patching. On Linux it
    /// is equivalent to [`Process::write`]: writes through `/proc/<pid>/mem`
    /// do not need a protection change. On Windows every page covering the
    /// range is temporarily changed to `PAGE_EXECUTE_READWRITE`, the bytes are
    /// written, and each page's exact original protection is restored on every
    /// exit path. Protection is captured and restored page by page, so a
    /// multi-page range with differing protections is handled correctly; do
    /// not hand-roll [`Process::protect`] + write + restore for code patches.
    ///
    /// A zero-length write is a no-op and does not access the target. A handle
    /// opened with [`ProcessAccess::ReadOnly`] rejects a non-empty write with
    /// [`Error::ReadOnly`] before any operating-system call.
    ///
    /// Protection changes are serialized per handle, so two calls through this
    /// handle cannot interleave their protect/write/restore steps. Calls through
    /// different handles to the same process are not coordinated; do not patch
    /// the same page through two handles at the same time.
    ///
    /// A failed or partial write can still have modified the target; the
    /// helper restores protection but cannot undo the bytes that were already
    /// written.
    ///
    /// # Instruction cache
    ///
    /// The helper changes page protection and writes bytes, but it does not
    /// flush the target's instruction cache: it never calls
    /// `FlushInstructionCache` on Windows or performs an equivalent
    /// synchronization on Linux. On x86 and x86_64, instruction and data caches
    /// are coherent, so the write is sufficient for the supported use case. On
    /// other architectures, including Windows and Linux on ARM64, the target
    /// may keep executing stale instructions; callers must not assume that
    /// patched code becomes visible. A cache-flush operation is not provided
    /// yet. The method remains available on every supported target; only the
    /// visibility guarantee is architecture-specific.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadOnly`] for a non-empty write through a read-only
    /// handle, [`Error::AddressRange`] when the range overflows, and
    /// [`Error::Write`] or [`Error::PartialWrite`] when the write itself fails
    /// and all changed protections were restored. Returns [`Error::Protect`]
    /// when the range is not fully committed or changing a page's protection
    /// fails and the pages already changed were restored, and
    /// [`Error::Unsupported`] when the platform cannot change protections.
    ///
    /// If restoring a page also fails, returns [`Error::CodeWrite`] with both
    /// the write/protection failure and the restore failure, or
    /// [`Error::CodeWriteRestore`] when the write succeeded but restoration
    /// failed.
    pub fn write_code(&self, address: Address, buffer: &[u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        if !self.is_writable() {
            return Err(Error::ReadOnly {
                pid: self.pid,
                operation: "Process::write_code",
            });
        }
        let _protection = self.protection_guard();
        validate_range(self.pid, address, buffer.len())?;
        let len = buffer.len();
        match self.inner.write_code(address.get(), buffer) {
            Ok(transferred) => ensure_complete_write(self.pid, address, len, transferred),
            Err(CodeWriteError::Failed(failure)) => {
                Err(self.code_write_failure(address, len, failure))
            }
            Err(CodeWriteError::RestoreFailedAfterWrite {
                transferred,
                restore,
                additional_restore_failures,
            }) => {
                let restore = Box::new(self.code_write_restore(restore));
                if transferred != len {
                    Err(Error::CodeWrite {
                        pid: self.pid,
                        address,
                        len,
                        failure: Box::new(Error::PartialWrite {
                            pid: self.pid,
                            address,
                            requested: len,
                            transferred,
                        }),
                        restore,
                        additional_restore_failures,
                    })
                } else {
                    Err(Error::CodeWriteRestore {
                        pid: self.pid,
                        address,
                        len,
                        transferred,
                        restore,
                        additional_restore_failures,
                    })
                }
            }
            Err(CodeWriteError::RestoreFailedAfterFailure {
                failure,
                restore,
                additional_restore_failures,
            }) => Err(Error::CodeWrite {
                pid: self.pid,
                address,
                len,
                failure: Box::new(self.code_write_failure(address, len, failure)),
                restore: Box::new(self.code_write_restore(restore)),
                additional_restore_failures,
            }),
        }
    }

    fn read_error(&self, address: Address, len: usize, source: memdiver_sys::Error) -> Error {
        match source.kind() {
            OsErrorKind::AddressSpaceReplaced => Error::AddressSpaceReplaced {
                pid: self.pid,
                address,
                len,
            },
            _ => match source.transferred() {
                Some(transferred) if transferred < len => Error::PartialRead {
                    pid: self.pid,
                    address,
                    requested: len,
                    transferred,
                },
                _ => Error::Read {
                    pid: self.pid,
                    address,
                    len,
                    source,
                },
            },
        }
    }

    fn write_error(&self, address: Address, len: usize, source: memdiver_sys::Error) -> Error {
        match source.kind() {
            OsErrorKind::AddressSpaceReplaced => Error::AddressSpaceReplaced {
                pid: self.pid,
                address,
                len,
            },
            _ => match source.transferred() {
                Some(transferred) if transferred < len => Error::PartialWrite {
                    pid: self.pid,
                    address,
                    requested: len,
                    transferred,
                },
                _ => Error::Write {
                    pid: self.pid,
                    address,
                    len,
                    source,
                },
            },
        }
    }

    fn code_write_failure(&self, address: Address, len: usize, failure: CodeWriteFailure) -> Error {
        match failure {
            CodeWriteFailure::Protect {
                address: page,
                len: page_len,
                source,
            } => match source.kind() {
                OsErrorKind::Unsupported => Error::Unsupported {
                    operation: "Process::write_code",
                    reason: "the platform does not allow one process to change another process's page protections",
                },
                _ => Error::Protect {
                    pid: self.pid,
                    address: Address::new(page),
                    len: page_len,
                    source: *source,
                },
            },
            CodeWriteFailure::Write(source)
                if source.kind() == OsErrorKind::AddressSpaceReplaced =>
            {
                Error::AddressSpaceReplaced {
                    pid: self.pid,
                    address,
                    len,
                }
            }
            CodeWriteFailure::Write(source) => match source.transferred() {
                Some(transferred) if transferred < len => Error::PartialWrite {
                    pid: self.pid,
                    address,
                    requested: len,
                    transferred,
                },
                _ => Error::Write {
                    pid: self.pid,
                    address,
                    len,
                    source: *source,
                },
            },
        }
    }

    fn code_write_restore(&self, restore: RestoreFailure) -> Error {
        Error::Protect {
            pid: self.pid,
            address: Address::new(restore.address),
            len: restore.len,
            source: *restore.source,
        }
    }

    /// Serializes protection-changing operations performed through this handle.
    ///
    /// Poisoning is ignored: a panic while holding the lock leaves the target's
    /// page protection in an unknown state, but the caller still gets a result
    /// rather than a second panic.
    fn protection_guard(&self) -> MutexGuard<'_, ()> {
        self.protection_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads a plain-old-data value from `address`.
    ///
    /// The value is copied out of an unaligned byte buffer, so `address` does
    /// not have to satisfy `align_of::<T>()`. Only [`Pod`] types are accepted:
    /// types such as `bool`, `char`, references and enums cannot be read safely
    /// from arbitrary memory because not every bit pattern is valid.
    ///
    /// ```compile_fail
    /// # use memdiver_core::{Address, Process};
    /// # fn demo(process: Process) {
    /// // `bool` is not `Pod`: not every bit pattern is a valid bool.
    /// let _: bool = process.read_value(Address::NULL).unwrap();
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::read_bytes`].
    pub fn read_value<T: Pod>(&self, address: Address) -> Result<T> {
        if size_of::<T>() == 0 {
            return Ok(T::zeroed());
        }
        // Read directly into the value's stack storage. This avoids a heap
        // allocation, a zero-fill and a second copy per typed read, which
        // matters for pointer chains and repeated value reads.
        let mut value = T::zeroed();
        self.read(address, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    /// Writes a plain-old-data value to `address`.
    ///
    /// The value's bytes are written without requiring alignment. As with
    /// [`Process::write`], a partial write can leave the target partially
    /// modified.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::write`].
    pub fn write_value<T: Pod>(&self, address: Address, value: T) -> Result<()> {
        if size_of::<T>() == 0 {
            return Ok(());
        }
        if !self.is_writable() {
            return Err(Error::ReadOnly {
                pid: self.pid,
                operation: "Process::write_value",
            });
        }
        self.write(address, bytemuck::bytes_of(&value))
    }

    /// Enumerates the committed memory regions of the target process.
    ///
    /// The returned vector is sorted by base address. The snapshot can become
    /// stale as soon as it is returned; it is not a lock on the target's
    /// mappings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Enumerate`] when the operating system cannot enumerate
    /// the regions or the procfs data cannot be parsed.
    pub fn regions(&self) -> Result<Vec<Region>> {
        let mut regions: Vec<Region> = self
            .inner
            .regions()
            .map_err(|source| Error::Enumerate {
                pid: self.pid,
                what: "memory regions",
                source,
            })?
            .into_iter()
            .map(Region::from_raw)
            .collect();
        regions.sort_by_key(Region::base);
        Ok(regions)
    }

    /// Returns a sorted region snapshot with binary-search lookups.
    ///
    /// Prefer this over repeated [`Process::region_at`] calls: the map
    /// enumerates the process once, while every `region_at` call re-enumerates.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::regions`].
    pub fn region_map(&self) -> Result<RegionMap> {
        Ok(RegionMap::new(self.regions()?))
    }

    /// Enumerates the regions needed by a scan.
    ///
    /// This avoids resolving module paths on Windows, where a normal
    /// [`Process::regions`] call would also enumerate every module.
    pub(crate) fn scan_regions(&self) -> Result<Vec<Region>> {
        let mut regions: Vec<Region> = self
            .inner
            .regions_without_paths()
            .map_err(|source| Error::Enumerate {
                pid: self.pid,
                what: "memory regions",
                source,
            })?
            .into_iter()
            .map(Region::from_raw)
            .collect();
        regions.sort_by_key(Region::base);
        Ok(regions)
    }

    /// Finds the committed region containing `address`.
    ///
    /// This convenience method re-enumerates the regions. Use
    /// [`Process::region_map`] when performing several lookups.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::regions`].
    pub fn region_at(&self, address: Address) -> Result<Option<Region>> {
        Ok(self.region_map()?.find(address).cloned())
    }

    /// Enumerates the executable modules loaded by the target process.
    ///
    /// The returned vector is sorted by load address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Enumerate`] when the operating system cannot enumerate
    /// the modules or the procfs data cannot be parsed.
    pub fn modules(&self) -> Result<Vec<Module>> {
        let mut modules: Vec<Module> = self
            .inner
            .modules()
            .map_err(|source| Error::Enumerate {
                pid: self.pid,
                what: "modules",
                source,
            })?
            .into_iter()
            .map(Module::from_raw)
            .collect();
        modules.sort_by_key(Module::base);
        Ok(modules)
    }

    /// Returns a sorted module snapshot with binary-search lookups.
    ///
    /// Prefer this over repeated [`Process::module_at`] calls: the map
    /// enumerates the process once, while every `module_at` call re-enumerates.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::modules`].
    pub fn module_map(&self) -> Result<ModuleMap> {
        Ok(ModuleMap::new(self.modules()?))
    }

    /// Finds the loaded module containing `address`.
    ///
    /// This convenience method re-enumerates the modules. Use
    /// [`Process::module_map`] when performing several lookups.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::modules`].
    pub fn module_at(&self, address: Address) -> Result<Option<Module>> {
        Ok(self.module_map()?.find(address).cloned())
    }

    /// Finds a module by exact name.
    ///
    /// Names are compared exactly, including case. Use the iterator returned by
    /// [`Process::modules`] with a custom comparison when case-insensitive
    /// matching is required (for example on Windows).
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::modules`].
    pub fn module(&self, name: &str) -> Result<Option<Module>> {
        Ok(self
            .modules()?
            .into_iter()
            .find(|module| module.name() == name))
    }

    /// Changes the protection of `len` bytes starting at `address`, returning
    /// the previous protection of the **first page** in the range.
    ///
    /// A range can span pages with different protections, but Windows reports
    /// only one previous protection value. Restoring with that single value can
    /// silently change the protection of the remaining pages. The returned
    /// [`Protection`] is also a semantic view: raw flags such as
    /// `PAGE_WRITECOPY` or `PAGE_NOCACHE` cannot be reconstructed from it.
    /// Use [`Process::write_code`] for a reversible code patch instead of
    /// hand-rolling protect + write + restore; it captures and restores raw
    /// protection page by page and reports a composite error when restoration
    /// fails.
    ///
    /// Linux does not allow one process to change another process's page
    /// protections; on Linux this returns [`Error::Unsupported`].
    ///
    /// Protection changes through one handle are serialized with
    /// [`Process::write_code`]. Separate handles to the same process are not
    /// coordinated, so do not change protection for the same page through
    /// different handles concurrently.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidLength`] for an empty range,
    /// [`Error::AddressRange`] when the range overflows,
    /// [`Error::InvalidProtection`] when the platform cannot represent the
    /// requested flags, [`Error::Protect`] when the operating system rejects the
    /// change, or [`Error::Unsupported`] on platforms without the operation.
    pub fn protect(
        &self,
        address: Address,
        len: usize,
        protection: Protection,
    ) -> Result<Protection> {
        if !self.is_writable() {
            return Err(Error::ReadOnly {
                pid: self.pid,
                operation: "Process::protect",
            });
        }
        if len == 0 {
            return Err(Error::InvalidLength {
                operation: "Process::protect",
                len,
            });
        }
        let _protection = self.protection_guard();
        validate_range(self.pid, address, len)?;
        self.inner
            .protect(address.get(), len, protection)
            .map_err(|source| match source.kind() {
                OsErrorKind::Unsupported => Error::Unsupported {
                    operation: "changing memory protection",
                    reason: "the platform does not allow one process to change another process's page protections",
                },
                OsErrorKind::InvalidProtection => Error::InvalidProtection {
                    pid: self.pid,
                    address,
                    len,
                    protection,
                    source,
                },
                _ => Error::Protect {
                    pid: self.pid,
                    address,
                    len,
                    source,
                },
            })
    }
}

/// Returns whether an opened process's image name matches the requested name.
///
/// An unavailable name is not a match: returning the handle would skip the
/// post-open verification required for a safe name-based open.
fn verified_name(actual: Option<&str>, requested: &str) -> bool {
    actual.is_some_and(|actual| name_matches(actual, requested))
}

fn ensure_complete_read(
    pid: u32,
    address: Address,
    requested: usize,
    transferred: usize,
) -> Result<()> {
    if transferred == requested {
        Ok(())
    } else {
        Err(Error::PartialRead {
            pid,
            address,
            requested,
            transferred,
        })
    }
}

fn ensure_complete_write(
    pid: u32,
    address: Address,
    requested: usize,
    transferred: usize,
) -> Result<()> {
    if transferred == requested {
        Ok(())
    } else {
        Err(Error::PartialWrite {
            pid,
            address,
            requested,
            transferred,
        })
    }
}

fn validate_range(pid: u32, address: Address, len: usize) -> Result<()> {
    let len64 = u64::try_from(len).map_err(|_| Error::AddressRange { pid, address, len })?;
    address
        .get()
        .checked_add(len64)
        .ok_or(Error::AddressRange { pid, address, len })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn process_is_send_and_sync() {
        assert_send_sync::<Process>();
    }

    // `Process::write_code` documents instruction-cache coherence only for x86
    // and x86_64. These cfg-gated tests pin that documented architecture
    // condition without requiring a cache flush on other targets, where the
    // helper remains available but makes no visibility promise. They are
    // compile-time architecture gates rather than behavioural tests: the
    // `cfg` selects the assertion, so they cannot fail on a supported target.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn write_code_cache_coherence_guarantee_applies_on_x86() {
        let arch = std::hint::black_box(std::env::consts::ARCH);
        assert!(matches!(arch, "x86" | "x86_64"), "unexpected arch {arch}");
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[test]
    fn write_code_cache_coherence_guarantee_does_not_apply_off_x86() {
        let arch = std::hint::black_box(std::env::consts::ARCH);
        assert!(!matches!(arch, "x86" | "x86_64"), "unexpected arch {arch}");
    }

    #[test]
    fn unavailable_names_are_never_verified() {
        assert!(!verified_name(None, "game.exe"));
        assert!(verified_name(Some("game.exe"), "game.exe"));
        assert!(!verified_name(Some("other.exe"), "game.exe"));
        #[cfg(windows)]
        assert!(verified_name(Some("GAME.EXE"), "game.exe"));
        #[cfg(not(windows))]
        assert!(!verified_name(Some("GAME.EXE"), "game.exe"));
    }

    #[test]
    fn access_levels_report_writability() {
        assert!(ProcessAccess::ReadWrite.is_writable());
        assert!(!ProcessAccess::ReadOnly.is_writable());
        assert_eq!(ProcessAccess::default(), ProcessAccess::ReadWrite);
    }

    #[test]
    fn detects_short_reads_and_writes() {
        let address = Address::new(0x1000);
        let error = ensure_complete_read(7, address, 16, 0).expect_err("short read");
        assert!(matches!(
            error,
            Error::PartialRead {
                requested: 16,
                transferred: 0,
                ..
            }
        ));
        assert!(ensure_complete_read(7, address, 16, 16).is_ok());

        let error = ensure_complete_write(7, address, 16, 15).expect_err("short write");
        assert!(matches!(
            error,
            Error::PartialWrite {
                requested: 16,
                transferred: 15,
                ..
            }
        ));
        assert!(ensure_complete_write(7, address, 16, 16).is_ok());
    }

    #[test]
    fn validates_address_ranges() {
        assert!(validate_range(7, Address::new(0), 16).is_ok());
        assert!(validate_range(7, Address::new(u64::MAX), 0).is_ok());
        assert!(validate_range(7, Address::new(u64::MAX), 1).is_err());
        assert_eq!(
            validate_range(7, Address::new(u64::MAX), 1)
                .expect_err("must fail")
                .to_string(),
            format!(
                "address range starting at {} with length 1 is invalid in process 7",
                Address::new(u64::MAX)
            )
        );
    }
}

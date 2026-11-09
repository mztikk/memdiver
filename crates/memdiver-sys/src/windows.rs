//! Windows backend built on `OpenProcess`, `ReadProcessMemory`,
//! `WriteProcessMemory`, `VirtualQueryEx`, `VirtualProtectEx` and
//! `EnumProcessModulesEx`.
//!
//! The kernel `HANDLE` stored in [`ProcessHandle`] pins the process instance.
//! Every operation, including module enumeration, goes through that handle, so
//! PID reuse cannot redirect a query to a different process.

use std::ffi::{OsString, c_void};
use std::fmt;
use std::fs::File;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BAD_LENGTH, ERROR_FILE_NOT_FOUND,
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_ADDRESS, ERROR_INVALID_HANDLE,
    ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_NOT_ALL_ASSIGNED, ERROR_NOT_FOUND,
    ERROR_PARTIAL_COPY, ERROR_PATH_NOT_FOUND, FILETIME, GetLastError, HANDLE, HMODULE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualProtectEx,
    VirtualQueryEx,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemInfo, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN, SYSTEM_INFO,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, IsWow64Process, IsWow64Process2, OpenProcess,
    OpenProcessToken, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, QueryFullProcessImageNameW, WaitForSingleObject,
};

use crate::{
    CodeWriteError, CodeWriteFailure, Error, ErrorKind, PointerWidth, Protection, RawModule,
    RawProcessInfo, RawRegion, RegionKind, RestoreFailure, io_message,
};

const READ_WRITE_ACCESS: PROCESS_ACCESS_RIGHTS = PROCESS_QUERY_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_SYNCHRONIZE;

const READ_ONLY_ACCESS: PROCESS_ACCESS_RIGHTS =
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SYNCHRONIZE;

const MAX_MODULE_ATTEMPTS: u32 = 8;
const MAX_PROCESS_ATTEMPTS: u32 = 8;

/// A pinned handle to a Windows process.
///
/// Created with [`ProcessHandle::open`]. Dropping the handle closes the kernel
/// handle but never terminates the target process.
pub struct ProcessHandle {
    pid: u32,
    handle: OwnedHandle,
    /// Creation time in 100-nanosecond intervals since 1601, captured at open.
    creation_time: u64,
}

impl fmt::Debug for ProcessHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessHandle")
            .field("pid", &self.pid)
            .field("creation_time", &self.creation_time)
            .finish_non_exhaustive()
    }
}

impl ProcessHandle {
    /// Opens a handle to the process with the given PID.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::NotFound`] for an invalid PID,
    /// [`ErrorKind::ProcessExited`] when the process has already terminated (its
    /// object can linger while another handle keeps it alive),
    /// [`ErrorKind::PermissionDenied`] when `OpenProcess` is denied, and
    /// [`ErrorKind::Other`] for any other Win32 failure.
    pub fn open(pid: u32) -> Result<Self, Error> {
        Self::open_with(pid, true)
    }

    /// Opens a handle to the process with the given PID.
    ///
    /// A read-only handle is opened with query, VM-read, and synchronize rights
    /// only. Write and protection operations then fail.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::NotFound`] for an invalid PID,
    /// [`ErrorKind::ProcessExited`] when the process has already terminated (its
    /// object can linger while another handle keeps it alive),
    /// [`ErrorKind::PermissionDenied`] when `OpenProcess` is denied, and
    /// [`ErrorKind::Other`] for any other Win32 failure.
    pub fn open_with(pid: u32, writable: bool) -> Result<Self, Error> {
        if pid == 0 {
            return Err(Error::new(
                ErrorKind::NotFound,
                None,
                "PID 0 does not name a user process".to_owned(),
            ));
        }

        let access = if writable {
            READ_WRITE_ACCESS
        } else {
            READ_ONLY_ACCESS
        };
        // SAFETY: OpenProcess has no pointer preconditions. The returned handle
        // is checked for null and owned by the ProcessHandle on success.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            let code = last_error_code();
            let kind = match code {
                ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND => ErrorKind::NotFound,
                ERROR_ACCESS_DENIED => ErrorKind::PermissionDenied,
                _ => ErrorKind::Other,
            };
            return Err(win_error_with_kind(code, kind));
        }

        let handle = OwnedHandle::new(handle);
        // A terminated process object can remain openable while another handle
        // keeps it alive. Reject it here instead of returning a handle whose
        // first operation fails.
        match unsafe { WaitForSingleObject(handle.as_handle(), 0) } {
            WAIT_OBJECT_0 => return Err(process_exited(pid)),
            WAIT_TIMEOUT => {}
            _ => return Err(last_error()),
        }
        let creation_time = process_creation_time(handle.as_handle())?;
        Ok(Self {
            pid,
            handle,
            creation_time,
        })
    }

    /// Returns the PID this handle was opened for.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the opaque process-instance identity captured at open time.
    ///
    /// This is the process creation time in 100-nanosecond intervals since
    /// 1601. It is stable for the lifetime of the process instance and changes
    /// when the PID is reused.
    #[must_use]
    pub fn start_time(&self) -> u64 {
        self.creation_time
    }

    /// Returns the pointer width of the target process.
    ///
    /// A 32-bit process (including x86-on-x64 and ARM32-on-ARM64) is reported
    /// as [`PointerWidth::Bits32`]; 64-bit targets are [`PointerWidth::Bits64`].
    /// `IsWow64Process2` supplies the machine pair, with `IsWow64Process` as a
    /// fallback when the call fails. `IsWow64Process2` is a static kernel32
    /// import, so the binary requires a Windows version that exports it
    /// (Windows 10 1709 or newer); the fallback is not a loader-compatibility
    /// mechanism for older systems.
    ///
    /// # Errors
    ///
    /// Returns an error when the Win32 query fails.
    pub fn pointer_width(&self) -> Result<PointerWidth, Error> {
        let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        // SAFETY: the handle is owned by `self` and both output parameters are
        // writable for one machine value.
        let succeeded = unsafe {
            IsWow64Process2(
                self.handle.as_handle(),
                &mut process_machine,
                &mut native_machine,
            )
        };
        if succeeded != 0 {
            return Ok(pointer_width_from_machines(process_machine, native_machine));
        }

        // Fall back when IsWow64Process2 fails. This is not a compatibility
        // path for systems that lack the export: the import is static, so the
        // binary would not load there.
        let mut wow64 = 0i32;
        // SAFETY: the handle is owned by `self` and `wow64` is writable.
        let succeeded = unsafe { IsWow64Process(self.handle.as_handle(), &mut wow64) };
        if succeeded == 0 {
            return Err(last_error());
        }
        Ok(if wow64 != 0 || cfg!(target_pointer_width = "32") {
            PointerWidth::Bits32
        } else {
            PointerWidth::Bits64
        })
    }

    /// Returns the executable path recorded by the operating system, when
    /// available.
    ///
    /// An empty path is reported as `None`; a failed query on the live pinned
    /// handle is an error so callers can distinguish "unavailable" from a
    /// verification failure.
    ///
    /// # Errors
    ///
    /// Returns the Win32 error when `QueryFullProcessImageNameW` fails.
    pub fn exe_path(&self) -> Result<Option<PathBuf>, Error> {
        query_image_path(self.handle.as_handle())
    }

    /// Reads up to `buffer.len()` bytes starting at `address`.
    ///
    /// Returns the number of bytes transferred. A short transfer is not an
    /// error at this layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the address cannot be represented on this host or
    /// when `ReadProcessMemory` fails. A failure that copied a prefix of the
    /// range exposes the count through [`Error::transferred`].
    pub fn read(&self, address: u64, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let address = checked_address(address, buffer.len())?;
        let mut transferred = 0;
        // SAFETY: the process handle is valid, `address` names a range of
        // `buffer.len()` bytes, and `buffer` is valid for writes of that size.
        let succeeded = unsafe {
            ReadProcessMemory(
                self.handle.as_handle(),
                address as *const c_void,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut transferred,
            )
        };
        if succeeded == 0 {
            let code = last_error_code();
            // A failed transfer against an exited process usually reports
            // ERROR_PARTIAL_COPY rather than ERROR_INVALID_HANDLE. Check the
            // pinned handle before classifying so a scan racing process exit
            // sees ProcessExited and aborts instead of skipping the chunk.
            self.ensure_alive()?;
            return Err(partial_transfer_error(code, transferred, buffer.len()));
        }
        Ok(transferred)
    }

    /// Writes up to `buffer.len()` bytes starting at `address`.
    ///
    /// Returns the number of bytes transferred. A short transfer is not an
    /// error at this layer. Page protection is not changed; use
    /// [`ProcessHandle::write_code`] when the target page is not writable.
    ///
    /// # Errors
    ///
    /// Returns an error when the address cannot be represented on this host or
    /// when `WriteProcessMemory` fails. A failure that copied a prefix of the
    /// range exposes the count through [`Error::transferred`].
    pub fn write(&self, address: u64, buffer: &[u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let address = checked_address(address, buffer.len())?;
        let mut transferred = 0;
        // SAFETY: the process handle is valid, `address` names a range of
        // `buffer.len()` bytes, and `buffer` is valid for reads of that size.
        let succeeded = unsafe {
            WriteProcessMemory(
                self.handle.as_handle(),
                address as *const c_void,
                buffer.as_ptr().cast(),
                buffer.len(),
                &mut transferred,
            )
        };
        if succeeded == 0 {
            let code = last_error_code();
            // See `read`: a short failed write after process exit reports
            // ERROR_PARTIAL_COPY, which must not be mistaken for an ordinary
            // unmapped range.
            self.ensure_alive()?;
            return Err(partial_transfer_error(code, transferred, buffer.len()));
        }
        Ok(transferred)
    }

    /// Writes `buffer` at `address`, temporarily making every page covering the
    /// range writable and executable, then restoring each page's original
    /// protection.
    ///
    /// Each page is protected individually with `PAGE_EXECUTE_READWRITE`, and
    /// the exact previous protection returned by `VirtualProtectEx` is retained
    /// for that page. This avoids relying on the single first-page value that a
    /// multi-page protection change returns, which would be wrong when pages
    /// have different protections. Restoration is attempted for every page that
    /// was changed, even when one restore fails.
    ///
    /// The write does not call `FlushInstructionCache`. On x86 and x86_64 the
    /// instruction and data caches are coherent; on other architectures,
    /// including ARM64, the target may execute stale instructions. No
    /// cache-flush operation is provided yet.
    ///
    /// # Errors
    ///
    /// Returns [`CodeWriteError::Failed`] when the write or a protection change
    /// fails and every protection that was already changed was restored.
    /// Returns [`CodeWriteError::RestoreFailedAfterWrite`] or
    /// [`CodeWriteError::RestoreFailedAfterFailure`] when at least one page
    /// could not be restored. The whole range is checked for committed memory
    /// before any protection is changed.
    pub fn write_code(&self, address: u64, buffer: &[u8]) -> Result<usize, CodeWriteError> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let len = buffer.len();
        let address_usize = checked_address(address, len)
            .map_err(|source| CodeWriteError::Failed(CodeWriteFailure::Write(Box::new(source))))?;
        let end = address_usize.checked_add(len).ok_or_else(|| {
            CodeWriteError::Failed(CodeWriteFailure::Write(Box::new(invalid_address(
                address, len,
            ))))
        })?;
        self.ensure_range_committed(address_usize, end)?;

        let page_size = system_page_size()?;
        let first_page = address_usize & !(page_size - 1);
        let last_page = (end - 1) & !(page_size - 1);
        let page_count = ((last_page - first_page) / page_size)
            .checked_add(1)
            .ok_or_else(|| {
                CodeWriteError::Failed(CodeWriteFailure::Protect {
                    address: first_page as u64,
                    len: end - address_usize,
                    source: Box::new(Error::malformed("page count overflowed")),
                })
            })?;

        let mut changed: Vec<(usize, PAGE_PROTECTION_FLAGS)> = Vec::new();
        changed.try_reserve_exact(page_count).map_err(|_| {
            CodeWriteError::Failed(CodeWriteFailure::Protect {
                address: first_page as u64,
                len: page_count.saturating_mul(page_size),
                source: Box::new(Error::new(
                    ErrorKind::Other,
                    None,
                    "could not allocate the page protection table",
                )),
            })
        })?;

        for index in 0..page_count {
            let page = index
                .checked_mul(page_size)
                .and_then(|offset| first_page.checked_add(offset))
                .ok_or_else(|| {
                    CodeWriteError::Failed(CodeWriteFailure::Protect {
                        address: first_page as u64,
                        len: end - address_usize,
                        source: Box::new(Error::malformed("page address overflowed")),
                    })
                })?;
            let mut previous: PAGE_PROTECTION_FLAGS = 0;
            // SAFETY: `page` is a page-aligned address inside a committed range
            // validated by `ensure_range_committed`, `page_size` is the system
            // page size, and `previous` is valid for one value.
            let succeeded = unsafe {
                VirtualProtectEx(
                    self.handle.as_handle(),
                    page as *const c_void,
                    page_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut previous,
                )
            };
            if succeeded == 0 {
                let failure = CodeWriteFailure::Protect {
                    address: page as u64,
                    len: page_size,
                    source: Box::new(last_error()),
                };
                let (restore, additional_restore_failures) =
                    self.restore_pages(&changed, page_size);
                return Err(match restore {
                    Some(restore) => CodeWriteError::RestoreFailedAfterFailure {
                        failure,
                        restore,
                        additional_restore_failures,
                    },
                    None => CodeWriteError::Failed(failure),
                });
            }
            changed.push((page, previous));
        }

        let write_result = self.write(address, buffer);
        let (restore, additional_restore_failures) = self.restore_pages(&changed, page_size);
        match (write_result, restore) {
            (Ok(transferred), None) => Ok(transferred),
            (Ok(transferred), Some(restore)) => Err(CodeWriteError::RestoreFailedAfterWrite {
                transferred,
                restore,
                additional_restore_failures,
            }),
            (Err(source), None) => Err(CodeWriteError::Failed(CodeWriteFailure::Write(Box::new(
                source,
            )))),
            (Err(source), Some(restore)) => Err(CodeWriteError::RestoreFailedAfterFailure {
                failure: CodeWriteFailure::Write(Box::new(source)),
                restore,
                additional_restore_failures,
            }),
        }
    }

    /// Restores every page in `pages` in reverse order.
    ///
    /// Returns the first restore failure and the number of additional failures.
    /// Every page is attempted even after a failure so that as little
    /// protection as possible is left modified.
    fn restore_pages(
        &self,
        pages: &[(usize, PAGE_PROTECTION_FLAGS)],
        page_size: usize,
    ) -> (Option<RestoreFailure>, usize) {
        let mut first = None;
        let mut additional = 0;
        for &(page, previous) in pages.iter().rev() {
            let mut ignored: PAGE_PROTECTION_FLAGS = 0;
            // SAFETY: every entry was successfully protected by `write_code`,
            // so `page` is page-aligned committed memory and `previous` is the
            // exact protection the OS returned for it.
            let succeeded = unsafe {
                VirtualProtectEx(
                    self.handle.as_handle(),
                    page as *const c_void,
                    page_size,
                    previous,
                    &mut ignored,
                )
            };
            if succeeded == 0 {
                let failure = RestoreFailure {
                    address: page as u64,
                    len: page_size,
                    source: Box::new(last_error()),
                };
                if first.is_none() {
                    first = Some(failure);
                } else {
                    additional += 1;
                }
            }
        }
        (first, additional)
    }

    /// Verifies that every byte in `address..end` belongs to committed memory
    /// before `write_code` changes any protection.
    fn ensure_range_committed(&self, address: usize, end: usize) -> Result<(), CodeWriteError> {
        let mut current = address;
        while current < end {
            // SAFETY: MEMORY_BASIC_INFORMATION is a plain-old-data Win32
            // struct; all-zero is a valid initial value.
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            // SAFETY: the handle is valid and `info` is writable for the given
            // size. `current` is a candidate user-mode address.
            let written = unsafe {
                VirtualQueryEx(
                    self.handle.as_handle(),
                    current as *const c_void,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                return Err(CodeWriteError::Failed(CodeWriteFailure::Protect {
                    address: current as u64,
                    len: end - current,
                    source: Box::new(last_error()),
                }));
            }
            if info.State != MEM_COMMIT {
                return Err(CodeWriteError::Failed(CodeWriteFailure::Protect {
                    address: current as u64,
                    len: end - current,
                    source: Box::new(Error::new(
                        ErrorKind::InvalidAddress,
                        None,
                        format!("address {current:#x} is not committed memory"),
                    )),
                }));
            }
            let base = info.BaseAddress as usize;
            let region_end = base.checked_add(info.RegionSize).ok_or_else(|| {
                CodeWriteError::Failed(CodeWriteFailure::Protect {
                    address: current as u64,
                    len: end - current,
                    source: Box::new(Error::malformed(
                        "VirtualQueryEx returned a wrapping region",
                    )),
                })
            })?;
            if base > current || region_end <= current {
                return Err(CodeWriteError::Failed(CodeWriteFailure::Protect {
                    address: current as u64,
                    len: end - current,
                    source: Box::new(Error::malformed(
                        "VirtualQueryEx returned a region that does not cover the queried address",
                    )),
                }));
            }
            current = region_end.min(end);
        }
        Ok(())
    }

    /// Returns whether the process is still running.
    ///
    /// This waits on the process handle with a zero timeout. A signaled handle
    /// means the process has exited; it does not inspect the exit code.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        // SAFETY: the handle is owned by `self` and valid for the call.
        let result = unsafe { WaitForSingleObject(self.handle.as_handle(), 0) };
        result == WAIT_TIMEOUT
    }

    /// Waits for the process to exit.
    ///
    /// Returns `true` when the process exited and `false` when the timeout
    /// expired first. `None` waits indefinitely. Every finite timeout is capped
    /// at `u32::MAX - 1` milliseconds so it never becomes Win32's `INFINITE`.
    ///
    /// # Errors
    ///
    /// Returns an error when `WaitForSingleObject` fails.
    pub fn wait_for_exit(&self, timeout: Option<Duration>) -> Result<bool, Error> {
        let millis = timeout_millis(timeout);
        // SAFETY: the handle is owned by `self` and valid for the call.
        let result = unsafe { WaitForSingleObject(self.handle.as_handle(), millis) };
        match result {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(last_error()),
        }
    }

    /// Enumerates the committed memory regions of the process.
    ///
    /// Region paths are populated from the module list when the region belongs
    /// to a loaded module. If the module list cannot be read, regions are still
    /// returned and their paths are `None`; the optional path metadata is best
    /// effort.
    ///
    /// # Errors
    ///
    /// Returns an error when the process is no longer alive, when the query
    /// fails immediately, or when `VirtualQueryEx` fails before the address
    /// space is exhausted.
    pub fn regions(&self) -> Result<Vec<RawRegion>, Error> {
        self.regions_with_paths(true)
    }

    /// Enumerates committed regions without resolving module paths.
    ///
    /// Range scans only need protection and range information; skipping the
    /// module list avoids a full module enumeration (and the per-module path
    /// queries) on every scan.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`ProcessHandle::regions`].
    pub fn regions_without_paths(&self) -> Result<Vec<RawRegion>, Error> {
        self.regions_with_paths(false)
    }

    fn regions_with_paths(&self, fill_paths: bool) -> Result<Vec<RawRegion>, Error> {
        self.ensure_alive()?;
        let modules = if fill_paths {
            self.modules().unwrap_or_default()
        } else {
            Vec::new()
        };
        let mut regions = Vec::new();
        let mut address = 0usize;

        loop {
            // SAFETY: MEMORY_BASIC_INFORMATION is a plain-old-data Win32 struct;
            // all-zero is a valid initial value.
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            // SAFETY: the handle is valid and `info` is writable for the given
            // size. `address` is a candidate user-mode address.
            let written = unsafe {
                VirtualQueryEx(
                    self.handle.as_handle(),
                    address as *const c_void,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                let code = last_error_code();
                if code == ERROR_INVALID_PARAMETER {
                    // At the end of the address space Windows reports
                    // ERROR_INVALID_PARAMETER. An immediate failure is a real
                    // error, not an empty region list.
                    if address == 0 {
                        return Err(win_error(code));
                    }
                    break;
                }
                return Err(win_error(code));
            }

            let base = info.BaseAddress as usize;
            let size = info.RegionSize;
            if size == 0 {
                return Err(Error::malformed(
                    "VirtualQueryEx returned a zero-sized region".to_owned(),
                ));
            }
            let next = base
                .checked_add(size)
                .ok_or_else(|| Error::malformed("VirtualQueryEx returned a wrapping region"))?;

            if info.State == MEM_COMMIT {
                let base64 = base as u64;
                let protection = page_to_protection(info.Protect);
                let kind = match info.Type {
                    MEM_IMAGE => RegionKind::Image,
                    MEM_MAPPED => RegionKind::Mapped,
                    _ => RegionKind::Private,
                };
                let path = if fill_paths {
                    let index = modules.partition_point(|module| module.base <= base64);
                    index
                        .checked_sub(1)
                        .and_then(|index| modules.get(index))
                        .filter(|module| module_contains(module, base64))
                        .map(|module| module.path.clone())
                } else {
                    None
                };
                regions.push(RawRegion {
                    base: base64,
                    size: size as u64,
                    protection,
                    kind,
                    path,
                });
            }

            if next <= address {
                return Err(Error::malformed(
                    "VirtualQueryEx returned a region without forward progress",
                ));
            }
            address = next;
        }

        self.ensure_alive()?;
        regions.sort_by_key(|region| region.base);
        Ok(regions)
    }

    /// Enumerates the modules loaded by the process.
    ///
    /// The module list is read through the pinned process handle with
    /// `EnumProcessModulesEx`, so PID reuse cannot redirect the query to a
    /// different process. A snapshot that changes while it is being copied is
    /// retried a bounded number of times.
    ///
    /// # Errors
    ///
    /// Returns an error when the process is no longer alive or the module list
    /// cannot be read.
    pub fn modules(&self) -> Result<Vec<RawModule>, Error> {
        self.ensure_alive()?;
        let mut attempt = 0;
        loop {
            match self.modules_once() {
                Ok(modules) => {
                    self.ensure_alive()?;
                    return Ok(modules);
                }
                Err(error) => {
                    // A retryable per-module error can also mean the process
                    // exited; check the pinned handle before treating it as a
                    // module-unload race. This turns a dead target into
                    // ProcessExited instead of a misleading NotFound/Other.
                    self.ensure_alive()?;
                    if is_retryable_module_error(&error) && attempt + 1 < MAX_MODULE_ATTEMPTS {
                        attempt += 1;
                    } else {
                        return Err(error);
                    }
                }
            }
        }
    }

    /// Reads a mapped module file and returns its bytes.
    ///
    /// The module must still be present in the pinned process's module list at
    /// `base` with the same path. The path must be an absolute local drive path;
    /// UNC/network paths and device-namespace paths are rejected before opening.
    /// The file must be a regular file no larger than
    /// [`MAX_MODULE_FILE_SIZE`](crate::MAX_MODULE_FILE_SIZE); this rejects
    /// devices, FIFOs and enormous files before parsing.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::MalformedData`] when the module is no longer
    /// present, the path is not a local drive path, or the file is not a
    /// bounded regular file, and the underlying operating-system error when the
    /// file cannot be opened or read.
    pub fn read_module_file(&self, base: u64, path: &Path) -> Result<Vec<u8>, Error> {
        let modules = self.modules()?;
        let present = modules
            .iter()
            .any(|module| module.base == base && module.path == path);
        if !present {
            return Err(Error::malformed(format!(
                "module mapping for {} is no longer present",
                path.display()
            )));
        }
        validate_module_file_path(path)?;
        let file = File::open(path).map_err(io_error)?;
        crate::read_bounded_file(file, crate::MAX_MODULE_FILE_SIZE, io_error)
    }

    /// Changes the protection of a memory range.
    ///
    /// Returns the previous protection of the **first page** in the range.
    /// Windows reports only one protection value even when the range spans
    /// pages with different protections, so the returned value is not enough to
    /// restore a multi-page range. Use [`ProcessHandle::write_code`] for a
    /// reversible code patch; it records the exact previous protection of every
    /// page separately.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidProtection`] when the requested combination
    /// cannot be represented by Windows: write-only ranges, and executable
    /// ranges that are writable but not readable. Execute-only and guard pages
    /// are representable. Returns [`ErrorKind::Other`] when `VirtualProtectEx`
    /// fails.
    pub fn protect(
        &self,
        address: u64,
        len: usize,
        protection: Protection,
    ) -> Result<Protection, Error> {
        if len == 0 {
            return Err(Error::new(
                ErrorKind::InvalidAddress,
                None,
                "cannot change the protection of an empty range".to_owned(),
            ));
        }
        let address = checked_address(address, len)?;
        let Some(new_protection) = protection_to_page(protection) else {
            return Err(Error::new(
                ErrorKind::InvalidProtection,
                None,
                format!("Windows cannot represent the protection {protection}"),
            ));
        };
        let mut old_protection: PAGE_PROTECTION_FLAGS = 0;
        // SAFETY: the handle is valid and the address/length pair passed the
        // checked conversion above. The out pointer is valid for one value.
        let succeeded = unsafe {
            VirtualProtectEx(
                self.handle.as_handle(),
                address as *const c_void,
                len,
                new_protection,
                &mut old_protection,
            )
        };
        if succeeded == 0 {
            return Err(last_error());
        }
        Ok(page_to_protection(old_protection))
    }

    fn modules_once(&self) -> Result<Vec<RawModule>, Error> {
        let mut required = 0u32;
        // SAFETY: the process handle is valid. Passing a null buffer with zero
        // size asks EnumProcessModulesEx for the required buffer size.
        let succeeded = unsafe {
            EnumProcessModulesEx(
                self.handle.as_handle(),
                ptr::null_mut(),
                0,
                &mut required,
                LIST_MODULES_ALL,
            )
        };
        if succeeded == 0 {
            return Err(last_error());
        }
        if required == 0 {
            return Ok(Vec::new());
        }

        let mut capacity = required;
        let mut path_buffer = vec![0u16; 32_768];
        for _ in 0..MAX_MODULE_ATTEMPTS {
            let slots = (capacity as usize / size_of::<HMODULE>()).max(1);
            let mut buffer = vec![ptr::null_mut(); slots];
            let mut returned = 0u32;
            let buffer_bytes = slots * size_of::<HMODULE>();
            // SAFETY: the process handle is valid, `buffer` holds `slots`
            // module handles, and its byte length is `buffer_bytes`.
            let succeeded = unsafe {
                EnumProcessModulesEx(
                    self.handle.as_handle(),
                    buffer.as_mut_ptr(),
                    buffer_bytes as u32,
                    &mut returned,
                    LIST_MODULES_ALL,
                )
            };
            if succeeded == 0 {
                return Err(last_error());
            }
            if returned as usize > buffer_bytes {
                capacity = returned;
                continue;
            }
            buffer.truncate(returned as usize / size_of::<HMODULE>());

            let mut modules = Vec::with_capacity(buffer.len());
            for module in buffer {
                modules.push(self.module_from_handle(module, &mut path_buffer)?);
            }
            modules.sort_by(|left, right| {
                left.base
                    .cmp(&right.base)
                    .then_with(|| left.name.cmp(&right.name))
            });
            return Ok(modules);
        }

        Err(Error::new(
            ErrorKind::Other,
            None,
            "the module list kept changing while it was enumerated".to_owned(),
        ))
    }

    fn module_from_handle(
        &self,
        module: HMODULE,
        path_buffer: &mut [u16],
    ) -> Result<RawModule, Error> {
        // SAFETY: MODULEINFO is plain-old-data and zero is a valid initial
        // value. The handle and module handle come from the same live process.
        let mut info: MODULEINFO = unsafe { zeroed() };
        // SAFETY: the process handle is valid and `info` is writable for the
        // given size.
        let succeeded = unsafe {
            GetModuleInformation(
                self.handle.as_handle(),
                module,
                &mut info,
                size_of::<MODULEINFO>() as u32,
            )
        };
        if succeeded == 0 {
            return Err(module_error(last_error_code()));
        }

        // SAFETY: the process and module handles are valid; the buffer is
        // writable for `path_buffer.len()` UTF-16 code units.
        let length = unsafe {
            GetModuleFileNameExW(
                self.handle.as_handle(),
                module,
                path_buffer.as_mut_ptr(),
                path_buffer.len() as u32,
            )
        };
        if length == 0 {
            let code = last_error_code();
            return Err(if code == 0 {
                Error::malformed("GetModuleFileNameExW returned an empty module path")
            } else {
                module_error(code)
            });
        }
        if length as usize >= path_buffer.len() {
            return Err(Error::malformed(
                "GetModuleFileNameExW truncated a module path longer than 32767 UTF-16 code units",
            ));
        }
        let path = PathBuf::from(wide_to_os_string(&path_buffer[..length as usize]));

        let base = info.lpBaseOfDll as usize as u64;
        let size = u64::from(info.SizeOfImage);
        let mappings = if size == 0 {
            Vec::new()
        } else {
            vec![(base, base.saturating_add(size))]
        };
        Ok(RawModule {
            name: file_name(&path),
            path,
            base,
            size,
            mappings,
        })
    }

    fn ensure_alive(&self) -> Result<(), Error> {
        if self.is_alive() {
            Ok(())
        } else {
            Err(process_exited(self.pid))
        }
    }
}

/// Enumerates visible processes.
///
/// The list is sorted by PID. Processes that exit or whose image path cannot be
/// queried are still listed when the snapshot provides their name; inaccessible
/// paths are reported as `None`.
///
/// # Errors
///
/// Returns an error when the process snapshot cannot be created or read after a
/// bounded number of retries.
pub fn processes() -> Result<Vec<RawProcessInfo>, Error> {
    let mut attempt = 0;
    loop {
        match process_snapshot() {
            Ok(processes) => return Ok(processes),
            Err(error)
                if is_retryable_process_error(&error) && attempt + 1 < MAX_PROCESS_ATTEMPTS =>
            {
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

fn process_snapshot() -> Result<Vec<RawProcessInfo>, Error> {
    // SAFETY: CreateToolhelp32Snapshot has no pointer preconditions. The
    // returned handle is checked and owned on success.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    let snapshot = OwnedHandle::new(snapshot);

    // SAFETY: PROCESSENTRY32W is plain-old-data and zero is valid.
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: the snapshot handle is valid and `entry` is writable.
    if unsafe { Process32FirstW(snapshot.as_handle(), &mut entry) } == 0 {
        let error = last_error();
        return if error.raw_code() == Some(ERROR_NO_MORE_FILES as i32) {
            Ok(Vec::new())
        } else {
            Err(error)
        };
    }

    let mut processes = Vec::new();
    let mut path_buffer = vec![0u16; 32_768];
    loop {
        let pid = entry.th32ProcessID;
        if pid != 0 {
            let metadata = limited_process_metadata(pid, &mut path_buffer);
            // Prefer the executable path's file name so the name and path are
            // derived from one process instance; fall back to the snapshot name.
            let name = metadata
                .exe_path
                .as_deref()
                .map(file_name)
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| wide_to_string(&entry.szExeFile));
            if !name.is_empty() || metadata.exe_path.is_some() {
                processes.push(RawProcessInfo {
                    pid,
                    name,
                    exe_path: metadata.exe_path,
                    start_time: metadata.start_time,
                });
            }
        }

        // SAFETY: PROCESSENTRY32W is plain-old-data and zero is valid.
        entry = unsafe { zeroed() };
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        // SAFETY: the snapshot handle is valid and `entry` is writable.
        if unsafe { Process32NextW(snapshot.as_handle(), &mut entry) } == 0 {
            let code = last_error_code();
            if code == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(win_error(code));
        }
    }

    processes.sort_by_key(|process| process.pid);
    Ok(processes)
}

/// Metadata queried with a short-lived limited-rights handle during process
/// enumeration. A failed query leaves the field `None`; it does not fail the
/// enumeration.
#[derive(Default)]
struct ProcessMetadata {
    exe_path: Option<PathBuf>,
    start_time: Option<u64>,
}

fn limited_process_metadata(pid: u32, buffer: &mut [u16]) -> ProcessMetadata {
    // SAFETY: OpenProcess has no pointer preconditions.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return ProcessMetadata::default();
    }
    let handle = OwnedHandle::new(handle);
    ProcessMetadata {
        exe_path: query_image_path_with_buffer(handle.as_handle(), buffer)
            .ok()
            .flatten(),
        start_time: process_creation_time(handle.as_handle()).ok(),
    }
}

/// Returns a process's creation time in 100-nanosecond intervals since 1601.
fn process_creation_time(handle: HANDLE) -> Result<u64, Error> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: the process handle is valid and all four output pointers are
    // writable for one FILETIME value.
    let succeeded =
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    if succeeded == 0 {
        return Err(last_error());
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn query_image_path(handle: HANDLE) -> Result<Option<PathBuf>, Error> {
    let mut buffer = vec![0u16; 32_768];
    query_image_path_with_buffer(handle, &mut buffer)
}

fn query_image_path_with_buffer(
    handle: HANDLE,
    buffer: &mut [u16],
) -> Result<Option<PathBuf>, Error> {
    let mut length = buffer.len() as u32;
    // SAFETY: the handle was opened for query access, the buffer is writable
    // for `length` UTF-16 units, and `length` is a valid in/out size.
    let succeeded = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut length)
    };
    if succeeded == 0 {
        return Err(last_error());
    }
    if length == 0 {
        return Ok(None);
    }
    if length as usize >= buffer.len() {
        return Err(Error::malformed(
            "QueryFullProcessImageNameW returned an unterminated path".to_owned(),
        ));
    }
    Ok(Some(PathBuf::from(wide_to_os_string(
        &buffer[..length as usize],
    ))))
}

/// Enables the current process's `SeDebugPrivilege`.
///
/// This only succeeds when the caller is an administrator and the privilege is
/// available to the token. It does not by itself guarantee access to a
/// protected process. The function changes the current process token and is
/// intentionally opt-in.
///
/// # Errors
///
/// Returns [`ErrorKind::PermissionDenied`] when the privilege is not assigned,
/// and other Win32 errors for token failures.
pub fn enable_debug_privilege() -> Result<(), Error> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle and `token` is
    // writable; ownership of the returned token handle is transferred to
    // `OwnedHandle` on success.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    };
    if opened == 0 {
        return Err(last_error());
    }
    let token = OwnedHandle::new(token);

    // SAFETY: LUID is plain-old-data and zero is a valid initial value.
    let mut luid = unsafe { zeroed() };
    // SAFETY: SE_DEBUG_NAME is a valid static UTF-16 string and `luid` is
    // writable. A null system name means the local system.
    let found = unsafe { LookupPrivilegeValueW(ptr::null(), SE_DEBUG_NAME, &mut luid) };
    if found == 0 {
        return Err(last_error());
    }

    // SAFETY: TOKEN_PRIVILEGES is plain-old-data and zero is valid.
    let mut privileges: TOKEN_PRIVILEGES = unsafe { zeroed() };
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // SAFETY: the token handle is valid, `privileges` describes one entry, and
    // null previous-state pointers are allowed with a zero buffer length.
    let changed = unsafe {
        AdjustTokenPrivileges(
            token.as_handle(),
            0,
            &privileges,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if changed == 0 {
        return Err(last_error());
    }
    // AdjustTokenPrivileges can report success even when the privilege was not
    // assigned to the token.
    let code = last_error_code();
    if code == ERROR_NOT_ALL_ASSIGNED {
        return Err(win_error_with_kind(code, ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn is_retryable_process_error(error: &Error) -> bool {
    error.raw_code() == Some(ERROR_BAD_LENGTH as i32)
}

fn is_retryable_module_error(error: &Error) -> bool {
    matches!(
        error.raw_code(),
        Some(code)
            if code == ERROR_PARTIAL_COPY as i32
                || code == ERROR_INSUFFICIENT_BUFFER as i32
                // A module unloaded between the snapshot and the per-module
                // query; the process handle itself is still valid.
                || code == ERROR_INVALID_HANDLE as i32
    )
}

/// Maps a per-module query failure.
///
/// `ERROR_INVALID_HANDLE` from `GetModuleInformation`/`GetModuleFileNameExW`
/// means the module disappeared, not that the process exited.
fn module_error(code: u32) -> Error {
    if code == ERROR_INVALID_HANDLE {
        win_error_with_kind(code, ErrorKind::NotFound)
    } else {
        win_error(code)
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.to_string_lossy().into_owned(),
        |name| name.to_string_lossy().into_owned(),
    )
}

fn module_contains(module: &RawModule, address: u64) -> bool {
    address >= module.base && address - module.base < module.size
}

/// Converts a UTF-16 buffer to an `OsString` without lossy replacement.
///
/// Windows paths can contain unpaired surrogates; keeping them as WTF-16 lets
/// `PathBuf` name the actual file instead of a replacement-character path.
fn wide_to_os_string(wide: &[u16]) -> OsString {
    let end = wide
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(wide.len());
    OsString::from_wide(&wide[..end])
}

fn wide_to_string(wide: &[u16]) -> String {
    let end = wide
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

fn checked_address(address: u64, len: usize) -> Result<usize, Error> {
    let address_usize = usize::try_from(address).map_err(|_| invalid_address(address, len))?;
    address_usize
        .checked_add(len)
        .ok_or_else(|| invalid_address(address, len))?;
    Ok(address_usize)
}

fn invalid_address(address: u64, len: usize) -> Error {
    Error::new(
        ErrorKind::InvalidAddress,
        None,
        format!("address range {address:#x}..+{len} is not representable on this host"),
    )
}

fn system_page_size() -> Result<usize, CodeWriteError> {
    // SAFETY: SYSTEM_INFO is a plain-old-data Win32 struct; all-zero is a valid
    // initial value.
    let mut info: SYSTEM_INFO = unsafe { zeroed() };
    // SAFETY: GetSystemInfo writes a SYSTEM_INFO to the provided pointer and
    // has no other preconditions.
    unsafe { GetSystemInfo(&mut info) };
    let page_size = info.dwPageSize as usize;
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(CodeWriteError::Failed(CodeWriteFailure::Protect {
            address: 0,
            len: 0,
            source: Box::new(Error::malformed(
                "GetSystemInfo returned an invalid page size",
            )),
        }));
    }
    Ok(page_size)
}

/// Maps the machine types reported by `IsWow64Process2` to a pointer width.
///
/// `IsWow64Process` cannot recognize 32-bit ARM processes on ARM64 Windows, so
/// the machine pair is authoritative here. A 64-bit process may report
/// `IMAGE_FILE_MACHINE_UNKNOWN`; its width then follows the native machine.
fn pointer_width_from_machines(process_machine: u16, native_machine: u16) -> PointerWidth {
    match process_machine {
        IMAGE_FILE_MACHINE_I386 | IMAGE_FILE_MACHINE_ARMNT => PointerWidth::Bits32,
        IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 => PointerWidth::Bits64,
        IMAGE_FILE_MACHINE_UNKNOWN => match native_machine {
            IMAGE_FILE_MACHINE_I386 => PointerWidth::Bits32,
            _ => PointerWidth::Bits64,
        },
        _ => {
            if cfg!(target_pointer_width = "32") {
                PointerWidth::Bits32
            } else {
                PointerWidth::Bits64
            }
        }
    }
}

/// Converts a timeout to the millisecond value expected by
/// `WaitForSingleObject`.
///
/// `None` is `INFINITE`. Every finite timeout is capped at `u32::MAX - 1`; the
/// value `u32::MAX` is `INFINITE`, so it must never be used for a finite wait
/// (a caller asking for exactly 4_294_967_295 ms must still time out).
fn timeout_millis(timeout: Option<Duration>) -> u32 {
    match timeout {
        None => u32::MAX,
        Some(timeout) => {
            let millis = timeout.as_millis();
            u32::try_from(millis)
                .unwrap_or(u32::MAX - 1)
                .min(u32::MAX - 1)
        }
    }
}

fn page_to_protection(page: PAGE_PROTECTION_FLAGS) -> Protection {
    const READABLE: PAGE_PROTECTION_FLAGS = PAGE_READONLY
        | PAGE_READWRITE
        | PAGE_WRITECOPY
        | PAGE_EXECUTE_READ
        | PAGE_EXECUTE_READWRITE
        | PAGE_EXECUTE_WRITECOPY;
    const WRITABLE: PAGE_PROTECTION_FLAGS =
        PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    const EXECUTABLE: PAGE_PROTECTION_FLAGS =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

    let mut protection = Protection::empty();
    if page & READABLE != 0 {
        protection |= Protection::READ;
    }
    if page & WRITABLE != 0 {
        protection |= Protection::WRITE;
    }
    if page & EXECUTABLE != 0 {
        protection |= Protection::EXECUTE;
    }
    if page & PAGE_GUARD != 0 {
        protection |= Protection::GUARD;
    }
    protection
}

fn protection_to_page(protection: Protection) -> Option<PAGE_PROTECTION_FLAGS> {
    if !Protection::all().contains(protection) {
        return None;
    }
    let read = protection.is_readable();
    let write = protection.is_writable();
    let execute = protection.is_executable();

    let mut page = match (read, write, execute) {
        (false, false, false) => PAGE_NOACCESS,
        (true, false, false) => PAGE_READONLY,
        (true, true, false) => PAGE_READWRITE,
        (false, false, true) => PAGE_EXECUTE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (false, true, false) | (false, true, true) => return None,
    };
    if protection.is_guarded() {
        // Windows rejects PAGE_NOACCESS | PAGE_GUARD; a guard page needs an
        // access right to guard.
        if page == PAGE_NOACCESS {
            return None;
        }
        page |= PAGE_GUARD;
    }
    Some(page)
}

fn last_error_code() -> u32 {
    // SAFETY: GetLastError has no preconditions and reads thread-local state.
    unsafe { GetLastError() }
}

/// Rejects module paths that would leave the local filesystem.
///
/// A target controls the path reported for its modules. Opening a UNC path
/// makes the inspecting process contact a remote SMB server (and may send NTLM
/// authentication); a device-namespace path opens a device before the
/// regular-file check can reject it. Only absolute local drive paths are opened.
fn validate_module_file_path(path: &Path) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::malformed(format!(
            "module path {} is not an absolute local path",
            path.display()
        )));
    }
    let prefix = match path.components().next() {
        Some(Component::Prefix(prefix)) => prefix.kind(),
        _ => {
            return Err(Error::malformed(format!(
                "module path {} is not an absolute local path",
                path.display()
            )));
        }
    };
    match prefix {
        Prefix::Disk(_) | Prefix::VerbatimDisk(_) => Ok(()),
        _ => Err(Error::malformed(format!(
            "module path {} is not a local drive path; network and device paths are not opened",
            path.display()
        ))),
    }
}

fn process_exited(pid: u32) -> Error {
    Error::new(
        ErrorKind::ProcessExited,
        None,
        format!("process {pid} has exited"),
    )
}

fn last_error() -> Error {
    win_error(last_error_code())
}

/// Builds a failed-transfer error and records any prefix the OS copied.
///
/// The failure remains an error; the count only lets the safe layer report
/// `PartialRead`/`PartialWrite` with both counts.
fn partial_transfer_error(code: u32, transferred: usize, requested: usize) -> Error {
    let error = win_error(code);
    if transferred > 0 && transferred < requested {
        error.with_transferred(transferred)
    } else {
        error
    }
}

fn io_error(error: std::io::Error) -> Error {
    match error.raw_os_error() {
        Some(code) => win_error(code as u32),
        None => Error::new(ErrorKind::Other, None, error.to_string()),
    }
}

fn win_error(code: u32) -> Error {
    let kind = match code {
        ERROR_ACCESS_DENIED => ErrorKind::PermissionDenied,
        ERROR_INVALID_HANDLE => ErrorKind::ProcessExited,
        ERROR_INVALID_ADDRESS | ERROR_PARTIAL_COPY => ErrorKind::InvalidAddress,
        ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => ErrorKind::NotFound,
        _ => ErrorKind::Other,
    };
    win_error_with_kind(code, kind)
}

fn win_error_with_kind(code: u32, kind: ErrorKind) -> Error {
    Error::new(kind, Some(code as i32), io_message(code as i32))
}

struct OwnedHandle(usize);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle as usize)
    }

    fn as_handle(&self) -> HANDLE {
        self.0 as HANDLE
    }
}

impl fmt::Debug for OwnedHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OwnedHandle").field(&self.0).finish()
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: every OwnedHandle is constructed from a non-null handle that
        // the caller transferred ownership of, and it is closed exactly once.
        let _ = unsafe { CloseHandle(self.as_handle()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_unpaired_surrogates_in_paths() {
        use std::os::windows::ffi::OsStrExt;

        let os = wide_to_os_string(&[0xD800, 0]);
        assert_eq!(os.encode_wide().collect::<Vec<_>>(), vec![0xD800]);
    }

    #[test]
    fn converts_wide_strings() {
        assert_eq!(
            wide_to_string(&[b'a' as u16, b'b' as u16, 0, b'x' as u16]),
            "ab"
        );
        assert_eq!(wide_to_string(&[]), "");
        assert_eq!(wide_to_string(&[b'a' as u16, b'b' as u16]), "ab");

        let emoji = "🦀";
        let mut utf16: Vec<u16> = emoji.encode_utf16().collect();
        utf16.push(0);
        assert_eq!(wide_to_string(&utf16), emoji);
    }

    #[test]
    fn finite_timeouts_never_become_infinite() {
        assert_eq!(timeout_millis(None), u32::MAX);
        assert_eq!(timeout_millis(Some(Duration::ZERO)), 0);
        assert_eq!(timeout_millis(Some(Duration::from_millis(1))), 1);
        assert_eq!(
            timeout_millis(Some(Duration::from_millis(u64::from(u32::MAX - 1)))),
            u32::MAX - 1
        );
        assert_eq!(
            timeout_millis(Some(Duration::from_millis(u64::from(u32::MAX)))),
            u32::MAX - 1
        );
        assert_eq!(timeout_millis(Some(Duration::MAX)), u32::MAX - 1);
    }

    #[test]
    fn classifies_missing_files_as_not_found() {
        for code in [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND] {
            assert_eq!(win_error(code).kind(), ErrorKind::NotFound);
            assert_eq!(win_error(code).raw_code(), Some(code as i32));
        }
    }

    #[test]
    fn classifies_partial_copy_as_invalid_address() {
        let error = win_error(ERROR_PARTIAL_COPY);
        assert_eq!(error.kind(), ErrorKind::InvalidAddress);
        assert_eq!(error.raw_code(), Some(ERROR_PARTIAL_COPY as i32));
    }

    #[test]
    fn module_unload_is_retryable_and_not_process_exit() {
        let error = module_error(ERROR_INVALID_HANDLE);
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert_eq!(error.raw_code(), Some(ERROR_INVALID_HANDLE as i32));
        assert!(is_retryable_module_error(&error));
        assert!(!is_retryable_process_error(&error));
    }

    #[test]
    fn maps_machine_types_to_pointer_width() {
        assert_eq!(
            pointer_width_from_machines(IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64),
            PointerWidth::Bits32
        );
        assert_eq!(
            pointer_width_from_machines(IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_ARM64),
            PointerWidth::Bits32
        );
        assert_eq!(
            pointer_width_from_machines(IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_AMD64),
            PointerWidth::Bits64
        );
        assert_eq!(
            pointer_width_from_machines(IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARM64),
            PointerWidth::Bits64
        );
        assert_eq!(
            pointer_width_from_machines(IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_ARM64),
            PointerWidth::Bits64
        );
        assert_eq!(
            pointer_width_from_machines(IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_I386),
            PointerWidth::Bits32
        );
    }

    #[test]
    fn maps_page_protections() {
        assert_eq!(page_to_protection(PAGE_NOACCESS), Protection::empty());
        assert_eq!(page_to_protection(PAGE_READONLY), Protection::READ);
        assert_eq!(
            page_to_protection(PAGE_READWRITE),
            Protection::READ | Protection::WRITE
        );
        assert_eq!(page_to_protection(PAGE_EXECUTE), Protection::EXECUTE);
        assert_eq!(
            page_to_protection(PAGE_EXECUTE_READ),
            Protection::READ | Protection::EXECUTE
        );
        assert_eq!(
            page_to_protection(PAGE_EXECUTE_READWRITE),
            Protection::READ | Protection::WRITE | Protection::EXECUTE
        );
        assert_eq!(
            page_to_protection(PAGE_READONLY | PAGE_GUARD),
            Protection::READ | Protection::GUARD
        );
        assert_eq!(
            page_to_protection(PAGE_EXECUTE_WRITECOPY),
            Protection::READ | Protection::WRITE | Protection::EXECUTE
        );
        assert_eq!(
            page_to_protection(PAGE_WRITECOPY),
            Protection::READ | Protection::WRITE
        );
        assert_eq!(
            page_to_protection(PAGE_NOACCESS | PAGE_GUARD),
            Protection::GUARD
        );
        assert_eq!(
            page_to_protection(PAGE_WRITECOPY | PAGE_GUARD),
            Protection::READ | Protection::WRITE | Protection::GUARD
        );
    }

    #[test]
    fn rejects_unrepresentable_protections() {
        assert_eq!(protection_to_page(Protection::empty()), Some(PAGE_NOACCESS));
        assert_eq!(
            protection_to_page(Protection::READ | Protection::WRITE),
            Some(PAGE_READWRITE)
        );
        assert_eq!(
            protection_to_page(Protection::READ | Protection::EXECUTE | Protection::GUARD),
            Some(PAGE_EXECUTE_READ | PAGE_GUARD)
        );
        assert_eq!(protection_to_page(Protection::EXECUTE), Some(PAGE_EXECUTE));
        assert_eq!(
            protection_to_page(Protection::EXECUTE | Protection::GUARD),
            Some(PAGE_EXECUTE | PAGE_GUARD)
        );
        assert_eq!(protection_to_page(Protection::WRITE), None);
        assert_eq!(
            protection_to_page(Protection::WRITE | Protection::EXECUTE),
            None
        );
        assert_eq!(protection_to_page(Protection::GUARD), None);
        assert_eq!(
            protection_to_page(Protection::GUARD | Protection::READ),
            Some(PAGE_READONLY | PAGE_GUARD)
        );
        assert_eq!(protection_to_page(Protection::from_bits_retain(0x80)), None);
    }

    #[test]
    fn rejects_network_and_device_module_paths() {
        for path in [
            Path::new(r"C:\Windows\System32\ntdll.dll"),
            Path::new(r"\\?\C:\very\long\module.dll"),
        ] {
            assert!(
                validate_module_file_path(path).is_ok(),
                "local drive path {path:?} must be accepted"
            );
        }
        for path in [
            Path::new(r"\\server\share\module.dll"),
            Path::new(r"\\.\PhysicalDrive0"),
            Path::new(r"relative\module.dll"),
            Path::new(r"C:relative\module.dll"),
        ] {
            assert!(
                validate_module_file_path(path).is_err(),
                "non-local path {path:?} must be rejected"
            );
        }
    }

    #[test]
    fn checks_module_containment() {
        let module = RawModule {
            name: "example.dll".to_owned(),
            path: PathBuf::from("C:\\example.dll"),
            base: 0x1000,
            size: 0x2000,
            mappings: vec![(0x1000, 0x3000)],
        };
        assert!(module_contains(&module, 0x1000));
        assert!(module_contains(&module, 0x2fff));
        assert!(!module_contains(&module, 0x2fff + 1));
        assert!(!module_contains(&module, 0x0fff));
    }

    #[test]
    fn checks_address_bounds() {
        assert!(checked_address(0x10, 0x10).is_ok());
        assert_eq!(
            checked_address(u64::MAX, 2).expect_err("must fail").kind(),
            ErrorKind::InvalidAddress
        );
    }
}

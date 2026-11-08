//! Windows backend built on `OpenProcess`, `ReadProcessMemory`,
//! `WriteProcessMemory`, `VirtualQueryEx`, `VirtualProtectEx` and
//! `EnumProcessModulesEx`.
//!
//! The kernel `HANDLE` stored in [`ProcessHandle`] pins the process instance.
//! Every operation, including module enumeration, goes through that handle, so
//! PID reuse cannot redirect a query to a different process.

use std::ffi::c_void;
use std::fmt;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_ADDRESS, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES,
    ERROR_NOT_ALL_ASSIGNED, ERROR_NOT_FOUND, ERROR_PARTIAL_COPY, GetLastError, HANDLE, HMODULE,
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
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, IsWow64Process, OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS,
    PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    QueryFullProcessImageNameW, WaitForSingleObject,
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
}

impl fmt::Debug for ProcessHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessHandle")
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

impl ProcessHandle {
    /// Opens a handle to the process with the given PID.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::NotFound`] for an invalid PID or a process that has
    /// already exited, [`ErrorKind::PermissionDenied`] when `OpenProcess` is
    /// denied, and [`ErrorKind::Other`] for any other Win32 failure.
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
    /// Returns [`ErrorKind::NotFound`] for an invalid PID or a process that has
    /// already exited, [`ErrorKind::PermissionDenied`] when `OpenProcess` is
    /// denied, and [`ErrorKind::Other`] for any other Win32 failure.
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

        Ok(Self {
            pid,
            handle: OwnedHandle::new(handle),
        })
    }

    /// Returns the PID this handle was opened for.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the pointer width of the target process.
    ///
    /// A 32-bit WOW64 process is reported as [`PointerWidth::Bits32`]; otherwise
    /// the width follows the bitness of the current host process.
    ///
    /// # Errors
    ///
    /// Returns an error when `IsWow64Process` fails.
    pub fn pointer_width(&self) -> Result<PointerWidth, Error> {
        let mut wow64 = 0i32;
        // SAFETY: the handle is owned by `self` and `wow64` is writable.
        let succeeded = unsafe { IsWow64Process(self.handle.as_handle(), &mut wow64) };
        if succeeded == 0 {
            return Err(last_error());
        }
        if wow64 != 0 || cfg!(target_pointer_width = "32") {
            Ok(PointerWidth::Bits32)
        } else {
            Ok(PointerWidth::Bits64)
        }
    }

    /// Returns the executable path recorded by the operating system, when
    /// available.
    ///
    /// # Errors
    ///
    /// This backend currently reports an unavailable path as `None` rather than
    /// an error; the result type leaves room for future diagnostics.
    pub fn exe_path(&self) -> Result<Option<PathBuf>, Error> {
        Ok(query_image_path(self.handle.as_handle()))
    }

    /// Reads up to `buffer.len()` bytes starting at `address`.
    ///
    /// Returns the number of bytes transferred. A short transfer is not an
    /// error at this layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the address cannot be represented on this host or
    /// when `ReadProcessMemory` fails.
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
            return Err(last_error());
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
    /// when `WriteProcessMemory` fails.
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
            return Err(last_error());
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
            .map_err(|source| CodeWriteError::Failed(CodeWriteFailure::Write(source)))?;
        let end = address_usize.checked_add(len).ok_or_else(|| {
            CodeWriteError::Failed(CodeWriteFailure::Write(invalid_address(address, len)))
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
                    source: Error::malformed("page count overflowed"),
                })
            })?;

        let mut changed: Vec<(usize, PAGE_PROTECTION_FLAGS)> = Vec::new();
        changed.try_reserve_exact(page_count).map_err(|_| {
            CodeWriteError::Failed(CodeWriteFailure::Protect {
                address: first_page as u64,
                len: page_count.saturating_mul(page_size),
                source: Error::new(
                    ErrorKind::Other,
                    None,
                    "could not allocate the page protection table",
                ),
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
                        source: Error::malformed("page address overflowed"),
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
                    source: last_error(),
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
            (Err(source), None) => Err(CodeWriteError::Failed(CodeWriteFailure::Write(source))),
            (Err(source), Some(restore)) => Err(CodeWriteError::RestoreFailedAfterFailure {
                failure: CodeWriteFailure::Write(source),
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
                    source: last_error(),
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
                    source: last_error(),
                }));
            }
            if info.State != MEM_COMMIT {
                return Err(CodeWriteError::Failed(CodeWriteFailure::Protect {
                    address: current as u64,
                    len: end - current,
                    source: Error::new(
                        ErrorKind::InvalidAddress,
                        None,
                        format!("address {current:#x} is not committed memory"),
                    ),
                }));
            }
            let base = info.BaseAddress as usize;
            let region_end = base.checked_add(info.RegionSize).ok_or_else(|| {
                CodeWriteError::Failed(CodeWriteFailure::Protect {
                    address: current as u64,
                    len: end - current,
                    source: Error::malformed("VirtualQueryEx returned a wrapping region"),
                })
            })?;
            if base > current || region_end <= current {
                return Err(CodeWriteError::Failed(CodeWriteFailure::Protect {
                    address: current as u64,
                    len: end - current,
                    source: Error::malformed(
                        "VirtualQueryEx returned a region that does not cover the queried address",
                    ),
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
    /// expired first. `None` waits indefinitely. Timeouts longer than roughly
    /// 49 days are capped by the Win32 millisecond timeout.
    ///
    /// # Errors
    ///
    /// Returns an error when `WaitForSingleObject` fails.
    pub fn wait_for_exit(&self, timeout: Option<Duration>) -> Result<bool, Error> {
        let millis = timeout.map_or(u32::MAX, |timeout| {
            let millis = timeout.as_millis();
            if millis == 0 {
                0
            } else {
                u32::try_from(millis).unwrap_or(u32::MAX - 1)
            }
        });
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
        self.ensure_alive()?;
        let modules = self.modules().unwrap_or_default();
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
                break;
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
                let path = modules
                    .iter()
                    .find(|module| module_contains(module, base64))
                    .map(|module| module.path.clone());
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
                Err(error)
                    if is_retryable_module_error(&error) && attempt + 1 < MAX_MODULE_ATTEMPTS =>
                {
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
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
                modules.push(self.module_from_handle(module)?);
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

    fn module_from_handle(&self, module: HMODULE) -> Result<RawModule, Error> {
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
            return Err(last_error());
        }

        let mut path_buffer = vec![0u16; 32_768];
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
                win_error(code)
            });
        }
        if length as usize >= path_buffer.len() {
            return Err(Error::malformed(
                "GetModuleFileNameExW truncated a module path longer than 32767 UTF-16 code units",
            ));
        }
        path_buffer.truncate(length as usize);
        let path = PathBuf::from(wide_to_string(&path_buffer));

        Ok(RawModule {
            name: file_name(&path),
            path,
            base: info.lpBaseOfDll as usize as u64,
            size: u64::from(info.SizeOfImage),
        })
    }

    fn ensure_alive(&self) -> Result<(), Error> {
        if self.is_alive() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::ProcessExited,
                None,
                format!("process {} has exited", self.pid),
            ))
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
    loop {
        let pid = entry.th32ProcessID;
        if pid != 0 {
            let name = wide_to_string(&entry.szExeFile);
            let exe_path = limited_image_path(pid);
            if !name.is_empty() || exe_path.is_some() {
                let name = if name.is_empty() {
                    exe_path.as_deref().map(file_name).unwrap_or_default()
                } else {
                    name
                };
                processes.push(RawProcessInfo {
                    pid,
                    name,
                    exe_path,
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

fn limited_image_path(pid: u32) -> Option<PathBuf> {
    // SAFETY: OpenProcess has no pointer preconditions.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let handle = OwnedHandle::new(handle);
    query_image_path(handle.as_handle())
}

fn query_image_path(handle: HANDLE) -> Option<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    // SAFETY: the handle was opened for query access, the buffer is writable
    // for `length` UTF-16 units, and `length` is a valid in/out size.
    let succeeded = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut length)
    };
    if succeeded == 0 || length == 0 || length as usize >= buffer.len() {
        return None;
    }
    buffer.truncate(length as usize);
    Some(PathBuf::from(wide_to_string(&buffer)))
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
    )
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
            source: Error::malformed("GetSystemInfo returned an invalid page size"),
        }));
    }
    Ok(page_size)
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
        page |= PAGE_GUARD;
    }
    Some(page)
}

fn last_error_code() -> u32 {
    // SAFETY: GetLastError has no preconditions and reads thread-local state.
    unsafe { GetLastError() }
}

fn last_error() -> Error {
    win_error(last_error_code())
}

fn win_error(code: u32) -> Error {
    let kind = match code {
        ERROR_ACCESS_DENIED => ErrorKind::PermissionDenied,
        ERROR_INVALID_HANDLE => ErrorKind::ProcessExited,
        ERROR_INVALID_ADDRESS => ErrorKind::InvalidAddress,
        ERROR_NOT_FOUND => ErrorKind::NotFound,
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
        assert_eq!(protection_to_page(Protection::from_bits_retain(0x80)), None);
    }

    #[test]
    fn checks_module_containment() {
        let module = RawModule {
            name: "example.dll".to_owned(),
            path: PathBuf::from("C:\\example.dll"),
            base: 0x1000,
            size: 0x2000,
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

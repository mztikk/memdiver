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

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_ADDRESS,
    ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, ERROR_PARTIAL_COPY,
    GetLastError, HANDLE, HMODULE, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualProtectEx,
    VirtualQueryEx,
};
use windows_sys::Win32::System::ProcessStatus::{
    EnumProcessModulesEx, GetModuleFileNameExW, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
};

use crate::{Error, ErrorKind, Protection, RawModule, RawRegion, RegionKind, io_message};

const ACCESS: PROCESS_ACCESS_RIGHTS = PROCESS_QUERY_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_SYNCHRONIZE;

const MAX_MODULE_ATTEMPTS: u32 = 8;

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
        if pid == 0 {
            return Err(Error::new(
                ErrorKind::NotFound,
                None,
                "PID 0 does not name a user process".to_owned(),
            ));
        }

        // SAFETY: OpenProcess has no pointer preconditions. The returned handle
        // is checked for null and owned by the ProcessHandle on success.
        let handle = unsafe { OpenProcess(ACCESS, 0, pid) };
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
    /// error at this layer.
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
    /// Returns the previous protection of the first page in the range. Windows
    /// reports only one protection value even when the range spans pages with
    /// different protections.
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

//! The safe process handle.

use std::fmt;
use std::mem::size_of;

use bytemuck::Pod;
use memoria_sys::ErrorKind as OsErrorKind;
use memoria_sys::ProcessHandle;

use crate::error::open_error;
use crate::{Address, Error, Module, Protection, Region, Result};

/// A handle to another process's memory.
///
/// Opening a process pins the underlying operating-system handle. On Linux the
/// `/proc/<pid>/mem` descriptor refers to the memory map that existed when the
/// handle was opened; on Windows the kernel `HANDLE` pins the process object.
/// Closing or dropping the `Process` never terminates or otherwise modifies the
/// target's execution state.
///
/// `Process` is [`Send`] and [`Sync`]: reads and writes use positional I/O on
/// Linux and thread-safe Win32 handle operations on Windows. Concurrent writes
/// to overlapping ranges are forwarded to the operating system without
/// additional ordering.
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
    pid: u32,
    inner: ProcessHandle,
}

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Process")
            .field("pid", &self.pid)
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
        let inner = ProcessHandle::open(pid).map_err(|source| open_error(pid, source))?;
        Ok(Self { pid, inner })
    }

    /// Returns the PID of the target process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
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
    /// read fails, [`Error::AddressRange`] when the range overflows, or
    /// [`Error::PartialRead`] when the operating system transfers fewer bytes
    /// than requested. On any error the contents of `buffer` are unspecified;
    /// inspect the `transferred` count in a partial-read error.
    pub fn read(&self, address: Address, buffer: &mut [u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        validate_range(address, buffer.len())?;
        let transferred = self
            .inner
            .read(address.get(), buffer)
            .map_err(|source| Error::Read {
                pid: self.pid,
                address,
                len: buffer.len(),
                source,
            })?;
        ensure_complete_read(self.pid, address, buffer.len(), transferred)
    }

    /// Reads `len` bytes from `address` into a new buffer.
    ///
    /// A zero-length read returns an empty vector without accessing the target.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::read`], plus [`Error::Allocation`]
    /// when the output buffer cannot be allocated.
    pub fn read_bytes(&self, address: Address, len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        validate_range(address, len)?;
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
    /// A zero-length write is a no-op and does not access the target.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error wrapped in [`Error::Write`] when the
    /// write fails, [`Error::AddressRange`] when the range overflows, or
    /// [`Error::PartialWrite`] when the operating system transfers fewer bytes
    /// than requested. A failed or partial write may already have modified the
    /// target.
    pub fn write(&self, address: Address, buffer: &[u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        validate_range(address, buffer.len())?;
        let transferred =
            self.inner
                .write(address.get(), buffer)
                .map_err(|source| Error::Write {
                    pid: self.pid,
                    address,
                    len: buffer.len(),
                    source,
                })?;
        ensure_complete_write(self.pid, address, buffer.len(), transferred)
    }

    /// Reads a plain-old-data value from `address`.
    ///
    /// The value is copied out of an unaligned byte buffer, so `address` does
    /// not have to satisfy `align_of::<T>()`. Only [`Pod`] types are accepted:
    /// types such as `bool`, `char`, references and enums cannot be read safely
    /// from arbitrary memory because not every bit pattern is valid.
    ///
    /// ```compile_fail
    /// # use memoria_core::{Address, Process};
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
        let bytes = self.read_bytes(address, size_of::<T>())?;
        Ok(bytemuck::pod_read_unaligned(&bytes))
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

    /// Finds the committed region containing `address`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::regions`].
    pub fn region_at(&self, address: Address) -> Result<Option<Region>> {
        let regions = self.regions()?;
        let index = regions.partition_point(|region| region.base() <= address);
        Ok(index
            .checked_sub(1)
            .and_then(|index| regions.get(index))
            .filter(|region| region.contains(address))
            .cloned())
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
    /// the previous protection.
    ///
    /// On Windows the previous protection is the value reported for the first
    /// page of the range. Linux does not allow one process to change another
    /// process's page protections; on Linux this returns
    /// [`Error::Unsupported`].
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
        if len == 0 {
            return Err(Error::InvalidLength {
                operation: "Process::protect",
                len,
            });
        }
        validate_range(address, len)?;
        self.inner
            .protect(address.get(), len, protection)
            .map_err(|source| match source.kind() {
                OsErrorKind::Unsupported => Error::Unsupported {
                    operation: "changing memory protection",
                    reason: "the platform does not allow one process to change another process's page protections",
                },
                OsErrorKind::InvalidProtection => Error::InvalidProtection {
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

fn validate_range(address: Address, len: usize) -> Result<()> {
    let len64 = u64::try_from(len).map_err(|_| Error::AddressRange { address, len })?;
    address
        .get()
        .checked_add(len64)
        .ok_or(Error::AddressRange { address, len })?;
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
        assert!(validate_range(Address::new(0), 16).is_ok());
        assert!(validate_range(Address::new(u64::MAX), 0).is_ok());
        assert!(validate_range(Address::new(u64::MAX), 1).is_err());
        assert_eq!(
            validate_range(Address::new(u64::MAX), 1)
                .expect_err("must fail")
                .to_string(),
            format!(
                "address range starting at {} with length 1 is invalid",
                Address::new(u64::MAX)
            )
        );
    }
}

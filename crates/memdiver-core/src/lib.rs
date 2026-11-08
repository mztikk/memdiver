//! Safe, cross-platform access to another process's memory.
//!
//! `memdiver-core` is the implementation behind the [`memdiver`] façade. It
//! exposes [`Process`], an owned handle that pins the target process, plus
//! typed reads and writes, memory-region queries, and module enumeration.
//!
//! # Platform support
//!
//! | Operation | Linux | Windows |
//! |-----------|-------|---------|
//! | Open a process and pin it | `/proc/<pid>/mem` descriptor | `OpenProcess` handle |
//! | Read / write bytes | `pread` / `pwrite` on `/proc/<pid>/mem` | `ReadProcessMemory` / `WriteProcessMemory` |
//! | Typed values | yes | yes |
//! | Memory regions | parsed from `/proc/<pid>/maps` | `VirtualQueryEx` |
//! | Modules | executable file mappings from `/proc/<pid>/maps` | `EnumProcessModulesEx` |
//! | Change protection | not supported | `VirtualProtectEx` |
//!
//! Transfers are all-or-nothing from the API's point of view: an operating
//! system transfer that is shorter than requested produces
//! [`Error::PartialRead`] or [`Error::PartialWrite`] rather than silently
//! truncating data.
//!
//! # Panics
//!
//! The library does not panic on operating-system input or caller-provided
//! addresses. Invalid addresses, overflow, permission failures and malformed
//! procfs data are returned as [`Error`] values.
//!
//! # Example
//!
//! ```
//! use memdiver_core::{Address, Process};
//!
//! # fn main() -> Result<(), memdiver_core::Error> {
//! let process = Process::open(std::process::id())?;
//! let magic = std::hint::black_box(0xDEAD_BEEFu32);
//! let address = Address::new((&magic as *const u32) as u64);
//! let value: u32 = process.read_value(address)?;
//! assert_eq!(value, magic);
//! # Ok(())
//! # }
//! ```
//!
//! [`memdiver`]: https://github.com/mztikk/external-memory-dsh/tree/main/crates/memdiver

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod address;
mod error;
mod module;
mod process;
mod region;

pub use address::Address;
pub use error::{Error, Result};
pub use module::Module;
pub use process::Process;
pub use region::Region;

pub use memdiver_sys::Error as OsError;
pub use memdiver_sys::ErrorKind as OsErrorKind;
pub use memdiver_sys::{Protection, RegionKind};

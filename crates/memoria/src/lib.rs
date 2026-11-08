//! Read and write the memory of another process on Linux and Windows.
//!
//! `memoria` is a safe, production-oriented library for external process
//! memory access. It pins the target process when you open it, performs
//! positional reads and writes through operating-system primitives, and reports
//! rich errors instead of panicking or silently truncating transfers.
//!
//! # Example
//!
//! ```
//! use memoria::{Address, Process};
//!
//! # fn main() -> Result<(), memoria::Error> {
//! let process = Process::open(std::process::id())?;
//! let magic = std::hint::black_box(0xDEAD_BEEFu32);
//! let address = Address::new((&magic as *const u32) as u64);
//!
//! let value: u32 = process.read_value(address)?;
//! assert_eq!(value, magic);
//! # Ok(())
//! # }
//! ```
//!
//! # Feature matrix
//!
//! | Operation | Linux | Windows |
//! |-----------|:-----:|:-------:|
//! | Open and pin a process | yes | yes |
//! | Read / write bytes | yes | yes |
//! | Typed `Pod` read / write | yes | yes |
//! | Enumerate memory regions | yes | yes |
//! | Enumerate modules | yes | yes |
//! | Query region protection | yes | yes |
//! | Change region protection | no | yes |
//!
//! # Operating-system permission model
//!
//! This crate does not elevate privileges. On Linux, opening `/proc/<pid>/mem`
//! goes through the kernel's ptrace access check: the caller must be able to
//! ptrace the target. With `kernel.yama.ptrace_scope = 1` that normally means
//! the target is a descendant of the caller (or the caller has
//! `CAP_SYS_PTRACE`). On Windows, `OpenProcess` is requested with query, read,
//! write, operation and synchronize rights; protected or higher-integrity
//! processes therefore require an elevated caller.
//!
//! Writing another process's memory can corrupt or crash it. The API is safe
//! with respect to Rust's memory model, but this inherent risk is the caller's
//! responsibility.
//!
//! # Crate layout
//!
//! * `memoria` — this façade and user-facing documentation.
//! * `memoria-core` — platform-independent safe API.
//! * `memoria-sys` — audited operating-system bindings (the only crate with
//!   `unsafe` code).
//!
//! [`Process`]: crate::Process

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub use memoria_core::{
    Address, Error, Module, OsError, OsErrorKind, Process, Protection, Region, RegionKind, Result,
};

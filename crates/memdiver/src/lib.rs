//! Read and write the memory of another process on Linux and Windows.
//!
//! `memdiver` is a safe, production-oriented library for external process
//! memory access. It pins the target process when you open it, discovers
//! processes by name, performs positional reads and writes through
//! operating-system primitives, applies reversible code patches with temporary
//! page-protection changes, scans memory for byte patterns, resolves pointer
//! chains, and reports rich errors instead of panicking or silently truncating
//! transfers.
//!
//! # Example
//!
//! ```
//! use memdiver::{Address, Process};
//!
//! # fn main() -> Result<(), memdiver::Error> {
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
//! | Enumerate processes / open by name | yes | yes |
//! | Open and pin a process | yes | yes |
//! | Read-only handles | yes | yes |
//! | Read / write bytes | yes | yes |
//! | Scoped code write with protection restore | yes | yes |
//! | Typed `Pod` read / write | yes | yes |
//! | Enumerate memory regions | yes | yes |
//! | Enumerate modules / module-at-address | yes | yes |
//! | Query region protection | yes | yes |
//! | Change region protection | no | yes |
//! | Pattern scanning (modules or all readable memory) | yes | yes |
//! | Typed value scanning | yes | yes |
//! | Batch reads and writes | yes | yes |
//! | Pointer width and pointer chains | yes | yes |
//! | Bounded C / UTF-16 strings | yes | yes |
//! | Wait for process exit | yes | yes |
//! | Enable debug privilege | no | yes |
//! | Module exports (PE / ELF) | yes | yes |
//!
//! `Process::write_code` is available on every supported target. Its
//! instruction-cache coherence guarantee is limited to x86/x86_64; see the
//! method documentation.
//!
//! # Operating-system permission model
//!
//! This crate does not elevate privileges. On Linux, opening `/proc/<pid>/mem`
//! goes through the kernel's ptrace access check: the caller must be able to
//! ptrace the target. With `kernel.yama.ptrace_scope = 1` that normally means
//! the target is a descendant of the caller (or the caller has
//! `CAP_SYS_PTRACE`). On Windows, `Process::open` requests query, read, write,
//! operation and synchronize rights; `Process::open_readonly` requests only the
//! query/read/synchronize rights it needs. Protected or higher-integrity
//! processes therefore require an elevated caller.
//!
//! Writing another process's memory can corrupt or crash it. The API is safe
//! with respect to Rust's memory model, but this inherent risk is the caller's
//! responsibility.
//!
//! # Crate layout
//!
//! * `memdiver` — this façade and user-facing documentation.
//! * `memdiver-core` — platform-independent safe API.
//! * `memdiver-sys` — audited operating-system bindings (the only crate with
//!   `unsafe` code).
//!
//! [`Process`]: crate::Process

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub use memdiver_core::{
    Address, Error, Export, Module, OsError, OsErrorKind, Pattern, PointerWidth, Process,
    ProcessAccess, ProcessInfo, Protection, Region, RegionKind, Result, ScanOptions,
    enable_debug_privilege,
};

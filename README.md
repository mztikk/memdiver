# memoria

[![CI](https://github.com/mztikk/external-memory-dsh/actions/workflows/ci.yml/badge.svg)](https://github.com/mztikk/external-memory-dsh/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](#toolchain)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`memoria` is a production-grade Rust library for reading and writing the memory
of another process on Linux and Windows.

It is built around a small set of guarantees that matter in real deployments:
a handle pins the process it was opened for, transfers are never silently
truncated, every OS failure keeps its platform error code and context, typed
access is restricted to plain-old-data, and every operation is covered by unit
or real cross-process integration tests.

## Features

| Operation | Linux | Windows |
|-----------|:-----:|:-------:|
| Open and pin a process by PID | yes | yes |
| Read bytes at an address | yes | yes |
| Write bytes at an address | yes | yes |
| Typed `Pod` reads and writes (unaligned safe) | yes | yes |
| Enumerate committed memory regions | yes | yes |
| Look up the region containing an address | yes | yes |
| Enumerate loaded modules | yes | yes |
| Look up a module by name | yes | yes |
| Read region protection | yes | yes |
| Change region protection | no | yes |
| Detect target exit | yes | yes |
| PID reuse cannot redirect access | yes | yes |

## Design highlights

* **Pinned handles.** On Linux the open handle keeps `/proc/<pid>/mem` and
  `/proc/<pid>` descriptors and the process start time, so later queries cannot
  silently attach to a process that reused the PID. On Windows the kernel
  `HANDLE` is kept for every operation, including module enumeration.
* **No silent truncation.** A read or write that transfers fewer bytes than
  requested returns `Error::PartialRead` / `Error::PartialWrite` with both
  counts. Nothing is quietly shortened.
* **Errors with context.** Operating-system failures identify the process,
  address, and length where those apply, and keep the original OS error as the
  `source()`. Raw `errno` / `GetLastError` values are available through
  `OsError::raw_code()`. Structural failures (overflow, allocation, unsupported
  operation) have dedicated variants.
* **Typed access is sound.** `read_value` and `write_value` accept only
  [`bytemuck::Pod`](https://docs.rs/bytemuck/latest/bytemuck/trait.Pod.html)
  types and copy through unaligned buffers; no references or invalid bit
  patterns can be constructed from arbitrary memory.
* **No panics on untrusted input.** Bad addresses, integer overflow, malformed
  procfs data, and permission failures are returned as errors.
* **Narrow unsafe surface.** `memoria` and `memoria-core` forbid `unsafe` code.
  All FFI and platform-specific logic lives in `memoria-sys`, with every
  `unsafe` block carrying a `SAFETY` justification.

## Installation

This workspace is not published on crates.io. The crates.io name `memoria` is
currently held by an unrelated 0.1.0 crate, so the installation snippet uses the
repository directly:

```toml
[dependencies]
memoria = { git = "https://github.com/mztikk/external-memory-dsh" }
```

Use a `path` dependency when working inside the workspace. Publishing the
façade will require a new crate name (or ownership of the existing one); the
crate names in this repository are kept as `memoria`, `memoria-core`, and
`memoria-sys`.

The crate is a façade over `memoria-core`, which in turn uses the low-level
`memoria-sys` bindings. Most users only need `memoria`.

## Quick start

```rust
use memoria::{Address, Process};

fn main() -> Result<(), memoria::Error> {
    // Open any process you are allowed to inspect.
    let process = Process::open(1234)?;

    // Raw bytes.
    let bytes = process.read_bytes(Address::new(0x7ff6_0000_0000), 64)?;
    println!("{bytes:02x?}");

    // Typed access, with no alignment requirement.
    let value: u32 = process.read_value(Address::new(0x7ff6_0000_0100))?;
    process.write_value(Address::new(0x7ff6_0000_0100), value + 1)?;

    // Memory map and modules.
    if let Some(region) = process.region_at(Address::new(0x7ff6_0000_0000))? {
        println!(
            "{:#x}..{:#x} {:?} {:?}",
            region.base().get(),
            region.end().get(),
            region.protection(),
            region.path()
        );
    }

    for module in process.modules()? {
        println!("{:#x} {:<10} {}", module.base().get(), module.size(), module.path().display());
    }

    Ok(())
}
```

Reading a value out of your own process is a self-contained way to try the API:

```rust
use memoria::{Address, Process};

fn main() -> Result<(), memoria::Error> {
    let process = Process::open(std::process::id())?;
    let magic = std::hint::black_box(0xDEAD_BEEFu32);
    let address = Address::new((&magic as *const u32) as u64);

    let value: u32 = process.read_value(address)?;
    assert_eq!(value, magic);
    Ok(())
}
```

## API overview

| Item | Purpose |
|------|---------|
| `Process::open(pid)` | Open and pin a process. |
| `Process::pid()` | PID of the pinned process. |
| `Process::is_alive()` | Liveness, zombie-aware on Linux. |
| `Process::read` / `write` | Byte-slice transfers. |
| `Process::read_bytes` | Allocate and read a byte range. |
| `Process::read_value` / `write_value` | Typed `Pod` transfers. |
| `Process::regions` | Committed regions, sorted by base address. |
| `Process::region_at` | Region containing an address. |
| `Process::modules` / `module` | Loaded executable modules. |
| `Process::protect` | Change page protection (Windows only). |
| `Address` | `u64` target address with checked arithmetic and hex formatting. |
| `Protection` | Read / write / execute / guard flags. |
| `Region`, `Module` | Snapshots with base, size, bounds checks, and metadata. |

All fallible operations return `memoria::Result<T>`, an alias for
`Result<T, memoria::Error>`.

### Errors

`Error` is non-exhaustive and keeps structured context:

```rust
use memoria::{Error, Process};

match Process::open(1234) {
    Ok(process) => { /* ... */ }
    Err(Error::ProcessNotFound { pid, .. }) => eprintln!("no process {pid}"),
    Err(Error::AccessDenied { pid, source }) => {
        eprintln!("access to {pid} denied: {source} (code {:?})", source.raw_code())
    }
    Err(error) => eprintln!("{error}"),
}
```

Transfers are all-or-nothing from the API's perspective. A short OS transfer is
an error, even though the caller's buffer may contain the bytes that were
transferred before the failure. On Windows the OS can copy a partial buffer and
then fail the call; `memoria` reports a write/read error in that case and does
not claim success.

## Platform details

### Linux

* Memory I/O uses positional `pread`/`pwrite` on `/proc/<pid>/mem`.
* Regions are parsed from `/proc/<pid>/maps`; paths are raw bytes and may be
  non-UTF-8. A deleted suffix (`" (deleted)"`) is removed.
* Modules are file-backed mappings with at least one executable segment. All
  segments of the same file are merged. Anonymous executable mappings are not
  modules.
* The process start time from `/proc/<pid>/stat` is captured at open time and
  compared on later queries, so a reused PID is not mistaken for the original
  process. Zombies are reported as not alive.
* `/proc/<pid>/mem` offsets are signed 64-bit values. Addresses or ranges above
  `i64::MAX` are rejected as invalid rather than wrapped.
* Linux has no API for changing another process's page protections;
  `Process::protect` returns `Error::Unsupported`.

### Requirements and troubleshooting (Linux)

Opening `/proc/<pid>/mem` is subject to the kernel's ptrace access check:

* The target normally must be a descendant of the calling process, or the caller
  must have `CAP_SYS_PTRACE`.
* With `kernel.yama.ptrace_scope = 1`, a non-descendant target is denied. A
  process can opt in with `prctl(PR_SET_PTRACER, ...)`, and a debugger can attach
  normally.
* `ptrace_scope = 2` requires root; `ptrace_scope = 3` disables attaching.
* Container runtimes may drop `CAP_SYS_PTRACE`, block `/proc/<pid>/mem`, or mount
  `/proc` with `hidepid=2`. Run the test suite outside such a sandbox, or grant
  the needed capability explicitly.
* Reading an address that is not mapped fails with an OS error; reading the
  entire requested range must succeed for `read` to return `Ok`.

Check the current setting with:

```sh
cat /proc/sys/kernel/yama/ptrace_scope
```

### Windows

* `OpenProcess` is requested with query, VM-read, VM-write, VM-operation, and
  synchronize access. If any right is denied, opening fails with
  `Error::AccessDenied`; run elevated when inspecting higher-integrity processes.
* Reads and writes use `ReadProcessMemory` and `WriteProcessMemory`.
* Regions come from `VirtualQueryEx`. Only committed regions are returned.
  Region paths are filled from the module list when the region belongs to a
  module; other mapped sections have no path.
* Modules come from `EnumProcessModulesEx` through the pinned handle, with
  `GetModuleInformation` and `GetModuleFileNameExW` for metadata. Enumeration is
  retried when the module list changes during a snapshot.
* `Process::protect` uses `VirtualProtectEx` and returns the previous protection
  of the first page in the range. Windows cannot represent write-only pages, or
  pages that are writable and executable without being readable; those requests
  return `Error::InvalidProtection`. Execute-only (`PAGE_EXECUTE`) and guard
  pages are representable.
* Guard pages are reported through `Protection::GUARD`.
* Protected processes, anti-cheat drivers, and kernel-only processes can deny
  even an elevated handle. That is reported as an OS error, not hidden.

## Security

This library gives the caller the ability to read and modify arbitrary memory in
a process it has been granted access to. The OS permission model is the only
access boundary. Writing to a live process can corrupt its state or crash it.
Reading memory can expose secrets. Use the library only with processes and data
you are authorized to access.

Typed reads are memory-safe in Rust because only `Pod` types are accepted, but
the bytes read can still be semantically invalid for the target program. The
library does not suspend, coordinate with, or otherwise make the target's
execution deterministic; concurrent target mutation can make a read
inconsistent. Use synchronization appropriate for the target if consistency is
required.

## Limitations

* Linux and Windows only. Other targets fail to compile with an explicit error.
* Processes are opened by PID; process-name enumeration and symbol resolution
  are out of scope.
* Linux cannot change page protections.
* There is no batching/vectored I/O API yet.
* Reads and writes are not atomic with respect to the target's own accesses.
* The library never attaches a debugger, suspends threads, or injects code.
* On a 32-bit Windows build, addresses above `usize::MAX` cannot be passed to
  the Win32 APIs, and module enumeration is subject to the OS's 32/64-bit
  limitations. Build `memoria` for the target's bitness when full access is
  required.

## Development

```sh
just check           # fmt, clippy, tests, doc tests, docs
just ci              # check + Windows cross-check/clippy
just example         # run the inspection example
```

The end-to-end suite starts a real child process (`memoria-fixture`), reads and
writes its heap buffer through the public API, and verifies the results from the
child's point of view. It also exercises regions, modules, protection changes
(Windows), liveness, PID-reuse safety, errors, and concurrent access.

Windows behaviour is type-checked and linted on Linux via the
`x86_64-pc-windows-gnu` target and fully executed on Windows in CI. See [AGENTS.md](AGENTS.md) and the
skills under [`.dsh/skills`](.dsh/skills) for the development rules.

### Workspace layout

```text
crates/memoria          façade crate and examples (no unsafe)
crates/memoria-core     safe, platform-independent API (no unsafe)
crates/memoria-sys      Linux/Windows bindings (the only unsafe code)
crates/memoria-integration-tests
                        fixture binary + end-to-end tests
```

Dependency direction is strictly one-way:
`memoria` → `memoria-core` → `memoria-sys`.

### Toolchain

The workspace uses Rust edition 2024 and has an MSRV of **1.85**. Formatting is
checked by `rustfmt`; lints are checked with `clippy -D warnings` for both the
host and the Windows target. Continuous integration runs the Linux suite, the
Windows suite, and an MSRV check.

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

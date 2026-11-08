# memdiver

[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](#toolchain)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`memdiver` is a production-grade Rust library for reading and writing the memory
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
| Enumerate processes and open by name | yes | yes |
| Read-only process handles | yes | yes |
| Read bytes at an address | yes | yes |
| Write bytes at an address | yes | yes |
| Typed `Pod` reads and writes (unaligned safe) | yes | yes |
| Enumerate committed memory regions | yes | yes |
| Look up the region containing an address | yes | yes |
| Enumerate loaded modules | yes | yes |
| Look up a module by name or address | yes | yes |
| Read region protection | yes | yes |
| Change region protection | no | yes |
| Wildcard pattern scan in one module or all modules | yes | yes |
| Wildcard pattern scan in all readable memory | yes | yes |
| Typed value scanning | yes | yes |
| Batch reads and writes | yes | yes |
| Pointer width detection and pointer chains | yes | yes |
| Bounded C strings and UTF-16LE strings | yes | yes |
| Wait for process exit | yes | yes |
| Enable SeDebugPrivilege (opt-in) | no | yes |
| Module exports (PE / ELF) | yes | yes |
| Detect target exit | yes | yes |
| PID reuse cannot redirect access | yes | yes |

## Design highlights

* **Pinned handles.** On Linux the open handle keeps `/proc/<pid>/mem` and
  `/proc/<pid>` descriptors and the process start time, so later queries cannot
  silently attach to a process that reused the PID. On Windows the kernel
  `HANDLE` is kept for every operation, including module enumeration.
* **Process discovery without silent ambiguity.** `Process::list` enumerates
  visible processes; `Process::open_by_name` opens only a unique match and
  reports candidates when several processes share a name.
* **Pattern scanning built in.** Wildcard and nibble-mask patterns can be
  scanned in one module, across every module (`find_pattern`), or across all
  readable memory, with chunked reads, alignment filtering, and result limits.
* **Navigation primitives.** Pointer-width detection, pointer-chain resolution,
  bounded C/UTF-16 string reads, and module-at-address lookup turn raw addresses
  into usable values.
* **Value and batch operations.** Typed values can be scanned directly, and
  independent ranges can be read or written in one call with the failing entry
  identified in the error.
* **Exports and process control.** Named PE/ELF module exports are resolved to
  live addresses; processes can be awaited and, on Windows, the caller can
  opt in to enabling `SeDebugPrivilege`.
* **Read-only handles.** Open with `ProcessAccess::ReadOnly` when writes are not
  needed; write and protection operations are rejected before any OS call.
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
* **Narrow unsafe surface.** `memdiver` and `memdiver-core` forbid `unsafe` code.
  All FFI and platform-specific logic lives in `memdiver-sys`, with every
  `unsafe` block carrying a `SAFETY` justification.

## Installation

The crate has not been published to crates.io yet. Until the first release, use
the repository directly:

```toml
[dependencies]
memdiver = { git = "https://github.com/mztikk/memdiver" }
```

The intended crates.io names are `memdiver`, `memdiver-core`, and
`memdiver-sys`. Use a `path` dependency when working inside the workspace.

The crate is a façade over `memdiver-core`, which in turn uses the low-level
`memdiver-sys` bindings. Most users only need `memdiver`.

## Quick start

```rust
use memdiver::{Address, Process};

fn main() -> Result<(), memdiver::Error> {
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

A typical discovery-and-scan workflow:

```rust
use memdiver::{Pattern, Process, ScanOptions};

fn main() -> Result<(), memdiver::Error> {
    // Fails with ProcessNameNotFound or AmbiguousProcessName instead of
    // silently picking a random process.
    let process = Process::open_by_name("game.exe")?;

    let pattern = Pattern::parse("48 8B 05 ?? ?? ?? ??")?;
    if let Some(hit) = process.find_pattern(&pattern)? {
        // find_pattern searches every loaded module; attribute the hit...
        let module = process.module_at(hit)?.expect("hit is in a module");
        println!("hit in {} at {hit}", module.name());

        // ...then follow a pointer chain. Offsets are applied after each
        // dereference; the last one is the final displacement.
        let width = process.pointer_width()?;
        let target = process.resolve_pointer_chain(hit, &[0x3, 0x10], width)?;

        // Strings are always bounded.
        let label = process.read_c_string(target, 256)?;
        println!("label bytes: {label:02x?}");

        let _all = process.find_patterns(&pattern, &ScanOptions::default())?;
    }

    Ok(())
}
```

Reading a value out of your own process is a self-contained way to try the API:

```rust
use memdiver::{Address, Process};

fn main() -> Result<(), memdiver::Error> {
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
| `Process::open(pid)` / `open_readonly(pid)` | Open and pin a process with read-write or read-only access. |
| `Process::list()` | Enumerate visible processes as `ProcessInfo`. |
| `Process::find_by_name(name)` | Find all matching processes. |
| `Process::open_by_name(name)` | Open the unique match, or return an ambiguity error. |
| `Process::pid()` / `name()` / `exe_path()` | Identity of the pinned process. |
| `Process::is_alive()` | Liveness, zombie-aware on Linux. |
| `Process::read` / `write` | Byte-slice transfers. |
| `Process::read_bytes` | Allocate and read a byte range. |
| `Process::read_value` / `write_value` | Typed `Pod` transfers. |
| `Process::regions` / `region_at` | Committed regions and address lookup. |
| `Process::modules` / `module` / `module_at` | Loaded executable modules and address lookup. |
| `Process::find_pattern` | First match across every loaded module. |
| `Process::find_patterns` | All matches across readable memory. |
| `Process::find_pattern_in_module` / `find_patterns_in_module` / `find_patterns_in_modules` | Module-scoped scans. |
| `Process::pointer_width` / `read_pointer` / `resolve_pointer_chain` | Pointer-width detection and chain traversal. |
| `Process::read_c_string` / `read_c_string_lossy` / `read_utf16_string` | Bounded string reads. |
| `Process::find_values` / `find_values_in_modules` / `find_values_in_module` | Search for typed values. |
| `Process::read_many` / `write_many` | Batched transfers with indexed errors. |
| `Process::wait_for_exit` | Block with an optional timeout until the process exits. |
| `Process::module_exports` / `module_export` | Named PE/ELF exports resolved to live addresses. |
| `enable_debug_privilege()` | Opt-in Windows `SeDebugPrivilege` helper (Linux: unsupported). |
| `Process::protect` | Change page protection (Windows only). |
| `Address` | `u64` target address with checked arithmetic and hex formatting. |
| `Pattern`, `ScanOptions` | Wildcard patterns and scan filtering. |
| `Export` | A named module export and its live address. |
| `PointerWidth`, `ProcessAccess`, `ProcessInfo` | Public supporting types. |
| `Protection` | Read / write / execute / guard flags. |
| `Region`, `Module` | Snapshots with base, size, bounds checks, and metadata. |

All fallible operations return `memdiver::Result<T>`, an alias for
`Result<T, memdiver::Error>`.

### Errors

`Error` is non-exhaustive and keeps structured context:

```rust
use memdiver::{Error, Process};

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
then fail the call; `memdiver` reports a write/read error in that case and does
not claim success.

## Platform details

### Linux

* Memory I/O uses positional `pread`/`pwrite` on `/proc/<pid>/mem`.
* Regions are parsed from `/proc/<pid>/maps`; paths are raw bytes and may be
  non-UTF-8. A deleted suffix (`" (deleted)"`) is removed.
* Modules are file-backed mappings with at least one executable segment. All
  segments of the same file are merged. Anonymous executable mappings are not
  modules.
* Process enumeration reads `/proc`, preferring the executable file name and
  falling back to `/proc/<pid>/comm`. Names match case-sensitively.
* Pointer width comes from the ELF class of `/proc/<pid>/exe`.
* Pattern and value scans read readable, non-guard regions in chunks with
  overlap. Unreadable regions and failed chunk reads are skipped; scans are
  best-effort over live memory.
* ELF exports are read from the module file, filtered to defined global/weak
  default/protected dynamic symbols, and rebased using the ELF type
  (`ET_DYN`: module base + symbol value; `ET_EXEC`: absolute symbol value).
* `wait_for_exit` blocks in `poll` on a pidfd, so an idle wait causes no
  periodic wakeups. Kernels before 5.3, or hosts whose seccomp policy denies
  `pidfd_open`, fall back to polling `/proc/<pid>/stat` at 10 ms intervals with
  start-time verification.
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
* Process enumeration uses a Tool Help process snapshot; image paths and
  metadata are queried with limited-rights handles where possible. Names match
  ASCII case-insensitively.
* Pointer width uses `IsWow64Process`.
* Pattern scans skip unreadable and guard regions and skip failed chunk reads.
* `Process::protect` uses `VirtualProtectEx` and returns the previous protection
  of the first page in the range. Windows cannot represent write-only pages, or
  pages that are writable and executable without being readable; those requests
  return `Error::InvalidProtection`. Execute-only (`PAGE_EXECUTE`) and guard
  pages are representable.
* Guard pages are reported through `Protection::GUARD`.
* `wait_for_exit` uses `WaitForSingleObject` on the pinned handle.
* PE exports are parsed from the module file and converted with
  `live_module_base + RVA`; forwarded exports and unnamed ordinals are skipped.
* `enable_debug_privilege` opens the current process token and enables
  `SeDebugPrivilege`. It is opt-in, never automatic, and normally requires
  administrator rights.
* Protected processes, anti-cheat drivers, and kernel-only processes can deny
  even an elevated handle. That is reported as an OS error, not hidden.

## Security

This library gives the caller the ability to read and modify arbitrary memory in
a process it has been granted access to. The OS permission model is the only
access boundary. Writing to a live process can corrupt its state or crash it.
Reading memory can expose secrets. Use the library only with processes and data
you are authorized to access. Prefer `Process::open_readonly` (or
`ProcessAccess::ReadOnly` via `Process::open_with`) when writes are not needed.
`enable_debug_privilege` is opt-in and broadens the current process's access; call
it only when the task actually needs it.

Typed reads are memory-safe in Rust because only `Pod` types are accepted, but
the bytes read can still be semantically invalid for the target program. The
library does not suspend, coordinate with, or otherwise make the target's
execution deterministic; concurrent target mutation can make a read
inconsistent. Use synchronization appropriate for the target if consistency is
required.

## Limitations

* Linux and Windows only. Other targets fail to compile with an explicit error.
* Processes are opened by PID or by a unique image name; matching by path or
  command line is out of scope.
* Linux cannot change page protections.
* Symbol resolution is limited to named module exports.
* Reads and writes are not atomic with respect to the target's own accesses.
* The library never attaches a debugger, suspends threads, or injects code.
* Pattern and value scans are best-effort snapshots of live memory: unreadable
  regions and failed chunk reads are skipped, and there is no
  cancellation/progress API yet.
* Module exports are parsed from the module file reported by the OS, not from
  the live mapped image. A deleted or replaced file, or PE forwarders and
  unnamed ordinal exports, can make the result incomplete or unavailable. ELF
  discovery currently relies on section headers being present.
* Batched transfers are sequential under the hood; they do not currently use
  scatter/gather syscalls.
* Linux wait-for-exit uses a pidfd where available and falls back to 10 ms
  procfs polling on older or restricted kernels. No portable exit code is
  exposed for non-child processes.
* `enable_debug_privilege` is Windows-only, opt-in, and normally requires
  administrator rights; it does not bypass protected-process policies.
* Process-name matching uses the platform's process image name. Linux
  `comm` names are only used when the executable name is unavailable.
* Wildcard patterns support whole bytes and nibble masks; there is no regular
  expression or string-mask syntax.
* Pointer chains use caller-supplied offsets; the library does not discover
  pointer paths.
* On a 32-bit Windows build, addresses above `usize::MAX` cannot be passed to
  the Win32 APIs, and module enumeration is subject to the OS's 32/64-bit
  limitations. Build `memdiver` for the target's bitness when full access is
  required.

## Development

```sh
just check           # fmt, clippy, tests, doc tests, docs
just ci              # check + Windows cross-check/clippy
just example         # run the inspection example
```

The end-to-end suite starts a real child process (`memdiver-fixture`), reads and
writes its heap buffer through the public API, and verifies the results from the
child's point of view. It also exercises process discovery and by-name opening,
read-only handles, regions, modules, pattern and typed-value scanning (including
a signature embedded in the fixture's executable), pointer chains, bounded
strings, batched transfers, waiting for exit, module exports against libc/ntdll,
protection changes (Windows), the opt-in privilege helper, liveness, PID-reuse
safety, errors, and concurrent access.

Windows behaviour is type-checked and linted on Linux via the
`x86_64-pc-windows-gnu` target and fully executed on Windows in CI. See
[AGENTS.md](AGENTS.md) and the skills under [`.dsh/skills`](.dsh/skills) for the
development rules.

### Workspace layout

```text
crates/memdiver          façade crate and examples (no unsafe)
crates/memdiver-core     safe, platform-independent API (no unsafe)
crates/memdiver-sys      Linux/Windows bindings (the only unsafe code)
crates/memdiver-integration-tests
                        fixture binary + end-to-end tests
```

Dependency direction is strictly one-way:
`memdiver` → `memdiver-core` → `memdiver-sys`.

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

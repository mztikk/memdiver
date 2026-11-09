# Changelog

All notable changes to this project are documented in this file.

This project follows [SemVer](https://semver.org/). Before 1.0, the minor
version is bumped for backwards-incompatible changes.

## [Unreleased]

### Fixed

- Windows: a failed `ReadProcessMemory`/`WriteProcessMemory` against an exited
  target is now classified as `ProcessExited` instead of a generic OS error, so
  a scan that races process exit aborts instead of returning a partial or empty
  result. `ERROR_PARTIAL_COPY` is classified as `InvalidAddress` while the
  target is still alive.

## [0.2.0] - 2026-11-08

This release contains breaking changes to the public error types and to several
edge-case behaviours. It also fixes the findings of the 0.1.1 code review.

### Breaking changes

- `Error::ModuleFile.source` is now `memdiver_sys::Error` instead of
  `std::io::Error`, so module-file failures retain the platform error kind and
  raw code. Match the source as an OS error and use `raw_code()` for the raw
  value.
- `Error::AddressRange` now carries `pid`, and `Error::InvalidProtection` now
  carries `pid`, `address` and `len`. Patterns that name every field must add
  the new fields; use `..` for forward compatibility. The `Error` enum remains
  `#[non_exhaustive]`.
- `Process::module_exports`/`module_export` now match module names using the
  platform rules (case-sensitive on Linux, ASCII case-insensitive on Windows)
  and return `Error::AmbiguousModuleName` when a name matches several loaded
  modules. Use the new `module_exports_of`/`module_export_of` methods with a
  `Module` snapshot to target one module unambiguously.
- `Process::open_by_name` no longer returns a handle when the opened process's
  image name cannot be read. An unreadable name is treated as unverified and the
  bounded retry ends in `Error::ProcessChanged`. On Windows, executable-path
  query failures are now errors instead of a silent `None`.
- On Linux, a target `execve` keeps the PID and start time but replaces the
  address space. The pinned memory descriptor then returns zero bytes; reads,
  writes and scans report the new `Error::AddressSpaceReplaced` instead of a
  silent `PartialRead { transferred: 0 }` or an empty scan. Reopen the process
  after an exec.
- `Process::read_c_string`/`read_utf16_string` now return the readable prefix
  when a chunk crosses the end of a mapping, instead of failing even when the
  terminator was readable. A first chunk that transfers zero bytes still fails.
- `Process::protect` on a read-only handle rejects an empty range with
  `Error::ReadOnly` before `Error::InvalidLength`, consistent with the rest of
  the read-only contract.
- Linux modules are now merged by `(device, inode)` rather than rendered path
  text. A deleted mapping and a replacement file at the same path are separate
  modules.
- Pattern scan methods coalesce adjacent readable regions before scanning;
  a pattern spanning a mapping boundary is now found.

### Added

- `RegionMap` and `ModuleMap`, with `Process::region_map` and
  `Process::module_map`, for repeated address/module lookups from one snapshot.
- `Process::module_exports_of` and `Process::module_export_of`.
- `Error::AddressSpaceReplaced`, `Error::ModuleParse`,
  `Error::AmbiguousModuleName` and `Error::PointerChainNull`.
- `memdiver_sys::MAX_MODULE_FILE_SIZE`, `ProcessHandle::read_module_file` and
  `ProcessHandle::regions_without_paths`.
- `ErrorKind::AddressSpaceReplaced` in `memdiver-sys`.

### Fixed

- Versioned ELF exports now prefer the default (non-hidden) symbol version
  instead of whichever compatibility definition appeared last in the dynamic
  symbol table.
- Module files are resolved through the target's mount namespace on Linux,
  checked against the mapped inode, and read only if they are regular files no
  larger than 1 GiB. Device files such as `/dev/zero`, FIFOs and replaced files
  are rejected before parsing.
- Linux `execve` invalidation of the pinned memory descriptor is detected and
  propagated by reads, writes and scans.
- Unmapped Linux addresses (`EIO` from `/proc/<pid>/mem`) are classified as
  `InvalidAddress` rather than a generic I/O error.
- Linux liveness polling reads `/proc/<pid>/stat` into a fixed buffer and only
  reads `/proc/<pid>/comm` when the executable name is unavailable.
- Windows pointer width uses the `IsWow64Process2` machine pair, so 32-bit ARM
  processes on ARM64 are reported as 32-bit.
- Windows module-unload races (`ERROR_INVALID_HANDLE` from a per-module query)
  are retried and reported as a vanished module, not process exit.
- A finite Windows wait timeout of exactly `u32::MAX` milliseconds no longer
  becomes `INFINITE`.
- Windows executable/module paths are preserved as WTF-16 instead of being
  lossily converted; path buffers are reused during enumeration.
- Windows scans no longer enumerate the module list when paths are not needed,
  and region path filling uses binary search.
- C and UTF-16 string reads tolerate a short transfer at the end of a mapping.
- Scan result growth is fallible (`Error::Allocation`); pattern parsing enforces
  its size limit before allocating and truncates malformed tokens in errors.
- `Process::read_value` reads directly into the value instead of allocating,
  zero-filling and copying a temporary buffer.
- Range and protection errors include process/range context; `write_value`
  identifies itself in read-only errors; allocation messages and batch
  allocation are more precise.
- Null pointer chains return `Error::PointerChainNull`.
- Documentation, `AGENTS.md` and the README were updated for the new contracts.

### Tests

- Added regression coverage for versioned exports, target-namespace/device
  module rejection, Linux exec invalidation, page-boundary strings, module
  merging by inode, valid-but-unreadable names, scan limits and range
  coalescing, 32-bit pointer reads, read-only target immutability, Linux code
  writes, Windows protection round trips and unaligned multi-page code writes.
- The fixture harness now has I/O timeouts, cleans up on handshake failures, and
  can launch a uniquely named copy of the fixture for deterministic name-based
  open tests.
- Stabilized wait/liveness tests and added start-time-mismatch, zombie,
  polling-fallback and `POLLHUP` coverage.

### Gate

Run on the release tree: `just check`, the Windows cross-check/clippy for
`x86_64-pc-windows-gnu`, the release test suite, and package-content checks.
MSRV 1.85 and native Windows runtime tests are covered by CI.

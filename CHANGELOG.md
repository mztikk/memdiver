# Changelog

All notable changes to this project are documented in this file.

This project follows [SemVer](https://semver.org/). Before 1.0, the minor
version is bumped for backwards-incompatible changes.

## [Unreleased]

### Breaking changes

- `memdiver_core::Error` gained context: `AddressSpaceReplaced` now keeps its
  `OsError` source, `ReadOnly` carries the rejected address/length,
  `InvalidLength` carries the PID and address, and `ModuleFile`/`ModuleExports`/
  `ModuleParse`/`ModuleNotFound`/`AmbiguousModuleName` name the PID (and module
  file path where known). Patterns that name every field need the new fields;
  use `..` for forward compatibility.
- `memdiver_sys::RawModule` gained a public `mappings` field with the module's
  exact half-open mapping ranges; `base`/`size` remain the containing span.
- `memdiver_sys::RawProcessInfo` gained a public `start_time` field. It is the
  process identity captured during enumeration (Linux start time, Windows
  creation time) and is used to verify name-based opens.
- `memdiver_sys::CodeWriteFailure::Protect.source`, `CodeWriteFailure::Write`
  and `RestoreFailure.source` now carry a boxed `memdiver_sys::Error`. The
  composite error is a cold path and boxing keeps `CodeWriteError` small now
  that `Error` carries a partial-transfer count; dereference the box when
  matching or constructing these values.

### Added

- `memdiver_sys::Error::transferred` exposes the number of bytes a failed
  Windows transfer copied before failing.
- `Process::start_time`, `ProcessInfo::start_time` and `ProcessHandle::start_time`
  expose the opaque process-instance identity captured at open/enumeration time.
- `Module::mappings` exposes a module's exact half-open mapping ranges.
- `Process::find_pattern_in_module_of`, `find_patterns_in_module_of` and
  `find_values_in_module_of` scan one `Module` snapshot unambiguously.
- `Process::open_by_name` now compares that identity with the opened handle, so
  a PID reused by a same-named process is rejected instead of silently attached
  to. A candidate whose identity or image name cannot be read is not verified.

### Fixed

- Windows: a failed `ReadProcessMemory`/`WriteProcessMemory` against an exited
  target is now classified as `ProcessExited` instead of a generic OS error, so
  a scan that races process exit aborts instead of returning a partial or empty
  result. `ERROR_PARTIAL_COPY` is classified as `InvalidAddress` while the
  target is still alive.
- Linux: module files are opened through the pinned `/proc/<pid>` directory
  descriptor instead of constructing a fresh `/proc/<pid>/root` path, so a PID
  reused during export resolution cannot redirect the lookup.
- Protection-changing operations (`write_code` and `protect`) are serialized per
  handle, so concurrent calls through one handle cannot interleave their
  protect/write/restore steps and leave a page writable and executable. Separate
  handles are documented as uncoordinated.
- Windows `ReadProcessMemory`/`WriteProcessMemory` failures that copy a prefix
  now expose the copied count (`memdiver_sys::Error::transferred`) and are
  reported as `PartialRead`/`PartialWrite` by the safe API instead of a generic
  read/write error.
- C and UTF-16 string reads return the readable prefix when a later chunk hits
  the end of a mapping, on every platform. Address-space replacement, process
  exit, range overflow and allocation failures still abort the read.
- Windows process enumeration now derives the name from the executable path when
  it is available, so the name and path metadata come from one process
  instance.
- `Module::contains` and module-scoped scans now use a module's exact mappings
  instead of its address span, so readable memory in an unmapped gap (or another
  module mapped inside the span) is no longer treated as part of the module.
- Windows `OpenProcess` can succeed for a terminated process while another
  handle keeps its object alive. `ProcessHandle::open` now checks the signaled
  state and returns `ProcessExited` instead of a handle whose first operation
  fails.
- Windows process/module errors classify `ERROR_FILE_NOT_FOUND` and
  `ERROR_PATH_NOT_FOUND` as `NotFound`, and module enumeration checks the pinned
  handle's liveness before retrying an `ERROR_INVALID_HANDLE`/`ERROR_PARTIAL_COPY`
  race, so an exited target reports `ProcessExited` instead of a vanished module.
- Windows module-file resolution rejects UNC/network and device-namespace paths
  before opening them, and refuses a PE file whose `SizeOfImage` does not match
  the loaded module. Both prevent a target-controlled path or replaced file from
  being parsed as the module.
- Scan performance: one chunk buffer is reused across ranges and chunks (it is no
  longer zero-filled before every read), module scans skip regions outside the
  module, all-wildcard patterns take a linear path, and Linux path-free scans no
  longer allocate a `PathBuf` per file-backed mapping. Core snapshots are no
  longer re-sorted after the backends sort them, `region_at`/`module_at` find
  one-shot entries without building a map, strings read 4 KiB chunks and move
  valid UTF-8 out of the buffer, and Windows `exe_path` grows a small buffer
  instead of allocating 64 KiB per call.
- Module-name resolution is shared by `Process::module`, module-scoped scans and
  exports. Names use the platform's process-name rules, and a name that matches
  several modules now returns `Error::AmbiguousModuleName` instead of silently
  selecting the first one.

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

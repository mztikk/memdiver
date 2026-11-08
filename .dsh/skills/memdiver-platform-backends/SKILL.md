---
name: memdiver-platform-backends
description: Use when adding or changing an operating-system operation in memdiver-sys, when Linux and Windows behaviour must stay in parity, or when reviewing unsafe platform code and its safe wrapper.
---

# Working on the platform backends

Read [AGENTS.md](../../../AGENTS.md) first. This skill covers the concrete
workflow for `crates/memdiver-sys`, the only crate allowed to contain `unsafe`.

## Contract

Both `src/linux.rs` and `src/windows.rs` expose the same `ProcessHandle` API
(plus a free `processes()` enumeration function):

```text
open(pid) -> Result<Self>
open_with(pid, writable: bool) -> Result<Self>
pid() -> u32
exe_path() -> Result<Option<PathBuf>>
pointer_width() -> Result<PointerWidth>
read(address: u64, &mut [u8]) -> Result<usize>
write(address: u64, &[u8]) -> Result<usize>
is_alive() -> bool
regions() -> Result<Vec<RawRegion>>
modules() -> Result<Vec<RawModule>>
protect(address, len, Protection) -> Result<Protection>
processes() -> Result<Vec<RawProcessInfo>>
```

The safe layer owns name matching, ambiguity handling, scan scoping, pointer
chains, and string framing; the sys layer returns raw facts only.

Reads and writes return the actual transfer count; the safe layer decides that
a short transfer is `PartialRead`/`PartialWrite`. Never hide a short transfer
inside the sys layer. Every error must be `memdiver_sys::Error` with an
`ErrorKind` and the raw OS code where one exists.

The pinned-instance invariants are not negotiable:

* Linux: keep `/proc/<pid>` and `/proc/<pid>/mem` open, capture the start time
  from `/proc/<pid>/stat`, and reject zombies/reused PIDs before reopening
  procfs files. Use `openat` relative to the directory descriptor. Open the
  memory file `O_RDONLY` for read-only handles.
* Windows: keep the kernel `HANDLE` and use it for every pinned query. Never
  enumerate modules or query regions by PID alone. Tool Help is acceptable only
  for the system-wide process snapshot; process handles used afterward are
  pinned and opened with only the required rights.

## Adding an operation

1. **Decide the platform matrix.** Implement it on both platforms, or return
   `ErrorKind::Unsupported` from the one that cannot support it. Never fake
   success.
2. **Write the raw implementation** in `linux.rs` and `windows.rs`. Keep it
   policy-free: no user-facing error strings beyond OS context, no `Address`
   type, no allocation decisions that belong to core.
3. **Validate before the OS call.** Check `u64` → `i64` (Linux) or
   `u64` → `usize` (Windows) conversions and length overflow. Capture
   `GetLastError` immediately after a failed Win32 call; retry `EINTR` on
   Linux.
4. **Add pure unit tests** for parsers, permission translation, address checks,
   and every malformed-input path you can construct without a live process.
5. **Add the safe wrapper** in `memdiver-core`: validate the range, add process /
   address / length context, map special `ErrorKind`s (`Unsupported`,
   `InvalidProtection`), and keep the OS error as `source`.
6. **Add an integration test** through `memdiver` using the fixture. If the
   operation is platform-specific, add the platform-gated test and ensure the
   other platform covers the `Unsupported` case. Use the
   `memdiver-integration-testing` skill.
7. **Update the README feature matrix** and the module-level docs. `AGENTS.md`
   and the skill must not drift from the code.
8. **Run the gates**:

   ```sh
   cargo fmt --all
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-targets --all-features
   cargo clippy --workspace --all-targets --all-features --target x86_64-pc-windows-gnu -- -D warnings
   RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
   ```

## Platform gotchas

### Linux

* Paths in `/proc/<pid>/maps` are bytes, not text. Parse with
  `OsString::from_vec`; skip the whitespace padding the kernel inserts between
  the inode and pathname; strip `" (deleted)"`. Test with a padded line and a
  `[heap]`/`[vdso]` special mapping.
* Parse `/proc/<pid>/stat` after the **last** `)`. The comm field may contain
  spaces and parentheses.
* Start time is token index 18 after the state token. Verify with a real
  process if you touch the parser.
* `pread`/`pwrite` can return `EINTR`; retry. Use `pread64`/`pwrite64` and
  reject ranges above `i64::MAX`.
* Modules are file-backed mappings with an executable segment; merge all
  segments of the same file. Anonymous executable mappings are not modules.
* Process enumeration reads `/proc`, prefers the executable basename, falls back
  to `comm`, skips vanished processes, and sorts by PID. Name matching is
  case-sensitive.
* Pointer width comes from the ELF class byte of `/proc/<pid>/exe`.
* Linux cannot change another process's protection: return
  `ErrorKind::Unsupported`.

### Windows

* `OpenProcess` returns null on failure. `GetLastError` must be read before any
  other call.
* Store handles as `usize` inside `OwnedHandle`; close exactly once in `Drop`.
  Do not derive `Copy`.
* `EnumProcessModulesEx` takes a byte count and may race with module
  load/unload. Retry a bounded number of times on `ERROR_PARTIAL_COPY` or
  `ERROR_INSUFFICIENT_BUFFER`; never loop forever.
* `VirtualQueryEx` reports free, reserved, and committed regions. Only return
  committed ones. `ERROR_INVALID_PARAMETER` after forward progress means the
  end of the address space; an immediate failure is not an empty map.
* `VirtualProtectEx` cannot represent write-only pages, or executable pages
  that are writable without being readable. Return `InvalidProtection` instead
  of widening access. Execute-only is `PAGE_EXECUTE`. The old protection is for
  the first page of a multi-page range.
* `WaitForSingleObject(handle, 0) == WAIT_TIMEOUT` is the liveness check. Do not
  use `GetExitCodeProcess == STILL_ACTIVE`; the exit code is ambiguous.
* Process enumeration uses `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`.
  Check the `INVALID_HANDLE_VALUE` sentinel, capture `GetLastError` immediately,
  and retry `ERROR_BAD_LENGTH`. Close the snapshot on every path. Query image
  paths with a short-lived limited-rights handle; failure means `None`.
* Pointer width uses `IsWow64Process`; a WOW64 target is 32-bit, otherwise use
  the host pointer width. Core pointer-chain arithmetic must respect the
  target width.
* `ReadProcessMemory`/`WriteProcessMemory` may copy partial data and still
  return failure. Report the error; never infer success from bytes copied.

## Unsafe review checklist

For every `unsafe` block:

* Is the handle/file descriptor valid and owned by the caller at that moment?
* Does the pointer cover exactly the length passed to the OS? Is the buffer
  writable/readable for that length?
* Are integer conversions checked before casting?
* Can the OS write back a garbage length? Validate or bound it before slicing.
* Does every error path still close resources exactly once?
* Is the wrapper `Send + Sync` only because the stored state is, not by accident?

Do not use `unsafe` to shortcut a borrow-checker error. Restructure.

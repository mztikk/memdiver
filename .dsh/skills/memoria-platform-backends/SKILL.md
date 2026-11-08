---
name: memoria-platform-backends
description: Use when adding or changing an operating-system operation in memoria-sys, when Linux and Windows behaviour must stay in parity, or when reviewing unsafe platform code and its safe wrapper.
---

# Working on the platform backends

Read [AGENTS.md](../../../AGENTS.md) first. This skill covers the concrete
workflow for `crates/memoria-sys`, the only crate allowed to contain `unsafe`.

## Contract

Both `src/linux.rs` and `src/windows.rs` expose the same `ProcessHandle` API:

```text
open(pid) -> Result<Self>
pid() -> u32
read(address: u64, &mut [u8]) -> Result<usize>
write(address: u64, &[u8]) -> Result<usize>
is_alive() -> bool
regions() -> Result<Vec<RawRegion>>
modules() -> Result<Vec<RawModule>>
protect(address, len, Protection) -> Result<Protection>
```

Reads and writes return the actual transfer count; the safe layer decides that
a short transfer is `PartialRead`/`PartialWrite`. Never hide a short transfer
inside the sys layer. Every error must be `memoria_sys::Error` with an
`ErrorKind` and the raw OS code where one exists.

The pinned-instance invariants are not negotiable:

* Linux: keep `/proc/<pid>` and `/proc/<pid>/mem` open, capture the start time
  from `/proc/<pid>/stat`, and reject zombies/reused PIDs before reopening
  procfs files. Use `openat` relative to the directory descriptor.
* Windows: keep the kernel `HANDLE` and use it for every query. Never enumerate
  modules or query regions by PID alone. Tool Help is PID-based and must not be
  reintroduced.

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
5. **Add the safe wrapper** in `memoria-core`: validate the range, add process /
   address / length context, map special `ErrorKind`s (`Unsupported`,
   `InvalidProtection`), and keep the OS error as `source`.
6. **Add an integration test** through `memoria` using the fixture. If the
   operation is platform-specific, add the platform-gated test and ensure the
   other platform covers the `Unsupported` case. Use the
   `memoria-integration-testing` skill.
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

# AGENTS.md

Operational guide for anyone — human or agent — changing this repository.

## Mission

`memdiver` is a production-grade Rust library that reads and writes another
process's memory on Linux and Windows. Correctness, predictable failure modes,
and auditability matter more than feature breadth. A change is not finished
until it is formatted, lint-clean, tested on Linux, type-checked (and ideally
linted) for Windows, documented, reviewed, and committed.

## Quality gate

Run from the repository root. Every command must pass without warnings.

```sh
just check           # fmt-check, clippy, tests, doc tests, docs
just windows-check   # cross-check every target for x86_64-pc-windows-gnu
just windows-clippy  # clippy for the Windows target
```

`just ci` runs all of the above. If the Windows target is not installed, install
it with `rustup target add x86_64-pc-windows-gnu`; do not silently skip the
check. A commit message must state which gate could not be run locally.

Never merge or commit:

* `#[ignore]`-marked tests added to hide a real failure,
* warnings that are silenced without a documented reason,
* new `unsafe` without a `// SAFETY:` justification,
* generated artifacts (`target/`, editor state, coverage output).

## Architecture

```text
memdiver (façade, examples)  ->  memdiver-core (safe API)  ->  memdiver-sys (OS)
memdiver-integration-tests   ->  memdiver (public API only)
```

Dependency direction is strictly one-way.

* `crates/memdiver-sys` owns every OS mechanism: file descriptors, Win32 handles,
  procfs parsing, memory APIs, module enumeration. It defines no polished
  end-user ergonomics and does no type reinterpretation for callers.
* `crates/memdiver-core` owns the safe API: `Address`, `Process`, `ProcessInfo`,
  `Error`, `Region`, `Module`, `Export`, `Pattern`, `ScanOptions`,
  pointer/string helpers, value and batch operations, export parsing
  (`goblin`), the wait wrapper, and typed I/O. It must not contain platform
  FFI.
* `crates/memdiver` re-exports the public API and holds user-facing
  documentation and examples.
* `crates/memdiver-integration-tests` contains the fixture binary and tests that
  use only the public API. The fixture must never import `memdiver` internals.

Adding platform code to `memdiver` or `memdiver-core`, or policy (name matching,
error context, allocation decisions) to `memdiver-sys`, is an architecture bug.

## Non-negotiable invariants

1. **Pin the process instance.** Linux keeps the `/proc/<pid>` directory and
   `/proc/<pid>/mem` descriptors plus the start time from `/proc/<pid>/stat`.
   Windows keeps the kernel `HANDLE`. Never replace a pinned operation with a
   fresh PID lookup. PID reuse must be harmless.
2. **No panics on untrusted input.** Library paths return `Result`. Panics are
   reserved for impossible internal invariants and documented public-contract
   violations. Test malformed procfs data, bad addresses, and overflow.
3. **No silent truncation.** If the OS transfers fewer bytes than requested,
   return `Error::PartialRead` / `Error::PartialWrite` with both counts. Never
   return `Ok(())` after a short transfer.
4. **Errors carry context.** Every OS failure surfaced to a user names the
   process, address, and length when relevant and keeps the raw platform error
   (and its `ErrorKind`) as a `source`. Do not flatten errors into strings.
5. **Typed access requires `Pod`.** Do not add a `read_struct`-style API for
   arbitrary `T`. Reads and writes go through unaligned byte buffers; never
   create a reference into foreign memory and never require target alignment.
6. **Platform parity is explicit.** If an operation is unavailable, return
   `Error::Unsupported` and document it in the README feature matrix. Never fake
   success. Keep the matrix current.
7. **RAII for every OS resource.** Linux `File`s and Windows handles close on
   drop, exactly once. No leaked handles on any error path.
8. **Liveness semantics are defined.** On Linux a zombie or a reused PID is not
   alive. On Windows liveness is the signaled state of the pinned handle.
9. **Zero-length and overflow contracts are explicit.** Zero-length reads,
   writes, and scoped code writes are no-ops that do not touch the target.
   Non-empty ranges that overflow `u64` are rejected before any OS call.
   `protect` rejects empty ranges.
10. **Read-only handles never write.** `ProcessAccess::ReadOnly` must reject
    `write`, `write_code`, `write_value` (for non-empty values) and `protect`
    with `Error::ReadOnly` before any OS call. Zero-length writes remain no-ops.
11. **Name-based opening is unambiguous.** `open_by_name` must never silently
    pick one of several matches; return the candidate list. Verify the opened
    image name after opening and retry a bounded number of times when the
    matching process is replaced.
12. **Scans are best-effort and bounded.** Pattern scans skip unreadable,
    guard, and failed-read chunks, protect against unbounded result vectors with
    `ScanOptions::max_results`, and overlap chunks so patterns spanning a chunk
    boundary are still found. `find_pattern` searches modules; `find_patterns`
    searches all readable memory; value scans use the same machinery with the
    value's exact native bytes. Document the difference and reject zero-sized
    values.
13. **Batched operations identify the entry.** `read_many` / `write_many`
    execute sequentially and an error names the zero-based entry index, the
    range, and the full underlying `Error` as its source. A read-only handle
    must reject a non-empty write batch before any entry is written.
14. **Wait semantics are defined.** Linux waits on a pinned pidfd when
    available, falling back to liveness polling with start-time verification;
    Windows waits on the pinned handle. `None` means indefinite, and a timeout
    returns `false` without treating the process as exited.
15. **Privilege changes are opt-in.** Never enable `SeDebugPrivilege`
    automatically. It is a separate function; on Linux it returns `Unsupported`.
16. **Exports reflect a module file, not patched memory.** Parse PE/ELF with
    `goblin` from the module path reported by the OS; document deleted/replaced
    files, PE forwarders, ordinal-only exports, and ELF section-header
    requirements. Rebase with the live module base and ELF type; bound every
    result to the live module range.
17. **No logging or printing from library code.** Callers decide how to report
    failures. Examples and the fixture may print.
18. **Scoped code writes restore protection.** `write_code` is the supported
    reversible code-patch helper. Linux writes through `/proc/<pid>/mem` and
    skips protection. Windows must protect every page covering the range with
    `PAGE_EXECUTE_READWRITE`, record the exact previous raw protection per page,
    write, and restore every page on every exit path. It must not rely on
    `protect`'s first-page return for a multi-page range. If writing or a later
    protection change fails, restore everything already changed and return the
    original failure; if a restore also fails, return a composite error that
    keeps both failures. A write that succeeds but cannot restore protection is
    also an error; never return `Ok(())` with a page still modified.

## Unsafe code policy

`memdiver` and `memdiver-core` are `#![forbid(unsafe_code)]`. All `unsafe` lives
in `memdiver-sys`.

* Every `unsafe` block starts with a `// SAFETY:` comment naming the invariant
  that makes it sound.
* Every public `unsafe fn` / `unsafe trait` has a `# Safety` section. Prefer
  keeping unsafe functions private; expose safe wrappers.
* Validate every pointer and length before passing it to the OS. Check integer
  conversions (`u64` → `i64` on Linux, `u64` → `usize` on Windows).
* Store Windows handles as `usize` in an owning `OwnedHandle` wrapper; this
  keeps `Process` automatically `Send + Sync` and makes accidental double-close
  harder. Never derive `Copy` for a handle wrapper.
* Do not use `unsafe` to work around the borrow checker. Restructure instead.
* Miri cannot execute these syscalls. Treat unsafe review as manual and
  adversarial.

## Platform notes and common traps

### Linux

* `/proc/<pid>/mem` offsets are `off_t`/`i64`; reject ranges above `i64::MAX`.
* Parse `/proc/<pid>/maps` as **bytes**, not UTF-8: paths can contain arbitrary
  non-UTF-8 bytes. Preserve paths with `OsString::from_vec`. The kernel pads the
  pathname column with spaces after the inode, so skip the entire whitespace run
  before the path. Remove the kernel's `" (deleted)"` suffix.
* `/proc/<pid>/stat` is not whitespace-safe: the command name can contain
  spaces, `)` and other punctuation. Split after the **last** `)`.
* The start time is field 22 (token index 18 after the state field). Verify
  against `/proc` whenever changing the parser.
* A module is the union of all mappings of one file that has at least one
  executable segment. Module base is the lowest mapping address; size spans all
  of its mappings. Do not treat every `mmap`ed data file as a module.
* Special mappings (`[heap]`, `[stack]`, `[vdso]`, ...) have no file path and
  are `RegionKind::Private`.
* `pread`/`pwrite` can return `EINTR`; retry. A short transfer is surfaced, not
  looped over silently.
* Opening `/proc/<pid>/mem` goes through the ptrace access check; failures are
  usually `AccessDenied`. `kernel.yama.ptrace_scope` and container capabilities
  are documented in the README.
* Process enumeration reads `/proc`. Prefer the executable basename from
  `/proc/<pid>/exe`, fall back to `/proc/<pid>/comm` (15-character limit), skip
  processes that vanish mid-scan, and sort by PID. Matching is case-sensitive.
* Pointer width comes from the ELF class byte of `/proc/<pid>/exe`. Reject
  non-ELF or unknown classes as malformed data.
* `wait_for_exit` opens and verifies a pidfd at handle open, then blocks in
  `poll`; this avoids periodic wakeups on Linux 5.3+. If `pidfd_open` is
  unavailable or denied, it polls `/proc/<pid>/stat` (10 ms) and uses the
  captured start time so a reused PID is not reported as exit. There is no exit
  code for non-child processes.
* ELF exports are parsed by `goblin` from the module file. Include defined
  global/weak dynamic symbols with default/protected visibility and function,
  object, or GNU IFUNC type. `ET_DYN` addresses are `module base + st_value`;
  `ET_EXEC` addresses are absolute. Skip symbols outside the live module range.
* Debug privileges are a Windows concept; return `Unsupported` on Linux.
* Linux cannot change another process's page protection. `protect` must return
  `Unsupported`. `write_code` is still supported: it writes through
  `/proc/<pid>/mem` and performs no protection step.

### Windows

* Request the rights you actually use: query, VM read, VM write, VM operation,
  synchronize. If a right is missing, opening fails with `AccessDenied`.
* `OpenProcess` returns a null handle on failure. `CreateToolhelp32Snapshot`
  returns `INVALID_HANDLE_VALUE`; process enumeration uses it, so check the
  sentinel, capture `GetLastError` immediately, and retry `ERROR_BAD_LENGTH`.
  Module enumeration must stay handle-based.
* Use the **pinned handle** for every query. Tool Help process enumeration is
  allowed because it is inherently a system-wide snapshot; process handles
  used afterward must be pinned. Tool Help module enumeration takes a PID and
  is therefore forbidden for module lists; use `EnumProcessModulesEx` +
  `GetModuleInformation` + `GetModuleFileNameExW`.
* During process enumeration, image paths and metadata may be queried with a
  short-lived `PROCESS_QUERY_LIMITED_INFORMATION` handle; failures mean `None`,
  not a failed enumeration. Match names ASCII case-insensitively.
* Pointer width comes from `IsWow64Process`; a WOW64 target is 32-bit, otherwise
  fall back to host pointer width.
* `wait_for_exit` uses `WaitForSingleObject` with millisecond timeouts; extremely
  long durations are capped by the Win32 range.
* `enable_debug_privilege` opens the current process token, looks up
  `SeDebugPrivilege`, and adjusts it. Check `ERROR_NOT_ALL_ASSIGNED` after a
  successful `AdjustTokenPrivileges` call; map it to `PermissionDenied`.
* PE exports are parsed by `goblin` from the module file. Include named,
  non-forwarded exports and rebase by `live module base + RVA`; validate the
  result stays inside the live image.
* Module enumeration can race with module load/unload. Retry a bounded number
  of times on `ERROR_PARTIAL_COPY` / `ERROR_INSUFFICIENT_BUFFER`; never loop
  forever.
* `VirtualQueryEx` iterates committed, reserved, and free ranges. Only report
  `MEM_COMMIT` regions. Reaching the end of the address space is signalled by
  `ERROR_INVALID_PARAMETER`; do not treat that as a generic failure, and do not
  treat an immediate failure as an empty map.
* `VirtualProtectEx` cannot express write-only pages, or executable pages that
  are writable without being readable. Return `InvalidProtection` for those
  combinations instead of widening access. Execute-only maps to `PAGE_EXECUTE`.
  The returned old protection describes **only the first page** of a multi-page
  range; pages in one range may have different protections. Callers that need to
  restore a range must track protection per page instead of trusting this value.
* `write_code` protects each page covering the request individually with
  `PAGE_EXECUTE_READWRITE`, records the exact raw `PAGE_PROTECTION_FLAGS` that
  `VirtualProtectEx` returns for that page, and restores each page with the same
  raw value. This preserves flags that the semantic `Protection` type cannot
  round-trip (for example `PAGE_WRITECOPY` and `PAGE_GUARD`). It must restore
  every changed page even when one restore fails, and report both the original
  failure and the restore failure. Preflight the committed range and fail before
  changing protection when a safe restore cannot be planned.
* Guard pages (`PAGE_GUARD`) are reported in `Protection::GUARD`.
* `PROCESS_VM_READ`/`WRITE` permission is checked by the OS. Protected processes
  and anti-cheat can deny access even to elevated callers.
* Windows `HANDLE`s remain valid after process exit; `WaitForSingleObject` with
  a zero timeout is the liveness check. A signaled handle means exited. Do not
  use `GetExitCodeProcess == STILL_ACTIVE`, which is ambiguous.
* `ReadProcessMemory`/`WriteProcessMemory` may copy a partial buffer and still
  fail. The call is an error; never infer success from a non-zero byte count.

## Testing requirements

Tests live at the lowest level that can observe the behaviour:

* **Pure logic** (address arithmetic, protection translation, procfs parsing,
  stat parsing, module merging, region containment, pattern parsing/matching,
  chunk scanning, pointer arithmetic, string framing, value encoding,
  batch-index error wrapping, export address rebasing, error formatting) gets
  unit tests next to the code, including boundary and malformed-input cases.
* **Platform behaviour** (process discovery, name-based open, read-only access,
  read, write, scoped code writes, typed I/O, value/batch operations, regions,
  modules, scanning, pointers, strings, wait-for-exit, privilege helper, exports,
  protection, liveness) gets end-to-end tests in
  `crates/memdiver-integration-tests` against the fixture child.
* Windows `write_code` tests must patch a known executable, non-writable code
  address with its existing bytes so a failed restore cannot change fixture
  behaviour, and must verify the page protection is identical afterwards. Do not
  patch different instruction bytes into the running fixture.
* Restoration-failure paths that cannot be forced deterministically through the
  OS need a unit test for the composite error construction and formatting, with
  a comment explaining why no end-to-end test forces the failure.
* Tests must use the public API from `memdiver`, not `memdiver-sys` internals.
* Tests must be deterministic and must not depend on enumeration order. Assert
  membership and sortedness, not exact whole-list contents.
* Use the fixture harness in `tests/common/mod.rs` instead of hand-rolling a
  child process. It handles the `READY` handshake and kills the child on drop.
* The fixture never touches its buffer while the parent is reading or writing
  it; preserve that property when extending the protocol.
* Concurrency tests must avoid overlapping writes to the same bytes. Reads may
  overlap freely.
* Every platform-specific path needs either a Linux test, a Windows test, or a
  documented reason why it can only be observed in CI. Windows-only code must
  at least compile under `cargo check --workspace --all-targets --target
  x86_64-pc-windows-gnu` and pass `cargo clippy` for that target.
* Do not add tests that require root, ptrace of a non-descendant, or a
  particular container capability. CI runs as an ordinary user.

When adding a public operation, add:

1. the `memdiver-sys` implementation for both platforms (or an explicit
   `Unsupported` error with a test),
2. the safe wrapper with docs and error context,
3. unit tests for pure edge cases,
4. an integration test through `memdiver`,
5. a row update in the README feature matrix,
6. a Windows cross-check/clippy run.

## Review checklist before every commit

Do this deliberately; do not skip it because the diff is small.

1. Read the entire diff (`git diff --cached`). Check for debug leftovers,
   unrelated changes, and missing docs.
2. Re-run `just check` and `just ci` after the final edit. Tests must pass on
   the exact tree being committed.
3. Re-audit every `unsafe` block: pointer validity, length validity, ownership,
   error paths, `Send`/`Sync` implications.
4. Walk the error paths: does every failure keep context and the OS source?
   Is a short transfer an error? Is a dead process detected?
5. Check the Linux vs Windows feature matrix, crate docs, README, and skills
   for drift. New public operations need a matrix row and an integration test.
6. Confirm tests actually exercise new behaviour; a test that cannot fail is a
   liability.
7. Verify `cargo fmt --all -- --check` and `cargo clippy ... -D warnings` are
   clean for the host and the Windows target.
8. Use a focused commit message (`feat:`, `fix:`, `test:`, `docs:`, `chore:`),
   no generated files, no `target/`.

## Commits and publishing

* Keep commits logically scoped. Tests and implementation for one change belong
  together; documentation-only changes can be separate.
* Do not commit if any gate fails. If a platform check is unavailable locally,
  state that in the commit body and rely on CI.
* Version bumps follow SemVer. Error enum additions are non-exhaustive and may
  be minor. Removing or renaming public items is a breaking change.
* The façade is intended to be published as `memdiver`, with `memdiver-core`
  and `memdiver-sys`. Verify that all three names are still available before the
  first release and publish in dependency order: sys, core, then façade.
* Before publishing, run `cargo package --list -p <crate>` and check that the
  package contains the README, license files, license metadata, and no
  fixture/test-only code.

## Toolchain

* Rust edition 2024, MSRV **1.85**, pinned `stable` in `rust-toolchain.toml`.
* Windows cross-check target: `x86_64-pc-windows-gnu`.
* Do not use language or standard-library features newer than the MSRV in
  library code. Test-only code may still be constrained by the CI MSRV job;
  prefer the same limits everywhere.

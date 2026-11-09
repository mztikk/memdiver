# memdiver — comprehensive code review

Date: 2026-11-09
Tree: `61be921` (`chore: release 0.2.0`), clean working tree.
Scope: all 10,421 lines of Rust in `crates/`, plus manifests, `justfile`, CI,
`README.md`, `AGENTS.md`, the three `.dsh/skills`, and the package contents.
No source files were modified; this document is the only added file.

## Method

* Line-by-line reading of every crate, in dependency order
  (`memdiver-sys` → `memdiver-core` → `memdiver` → integration tests).
* Re-audited every `unsafe` block in `memdiver-sys` against the AGENTS.md
  checklist (pointer/length validity, checked conversions, ownership, error
  paths, `Send`/`Sync`).
* Cross-checked the state machine of the scanner with an exhaustive model
  (patterns of length 1–5, data sizes 6–40, a marker at every position, wildcard
  anchors at every index, chunk size deliberately shrunk to 4). Result: **0
  missed or duplicated matches** — the chunk/overlap/anchor arithmetic is
  correct.
* Probed the relevant OS behaviour on this host: `pread` on `/proc/<pid>/mem`
  across a mapping end returns a *short* count (so `PartialRead` is reachable on
  Linux); reads on a dead process return 0 bytes (the `AddressSpaceReplaced`
  detection is sound); `openat` relative to a pinned `/proc/<pid>` fd resolves
  `root/...` (so the M2 fix is feasible); `readlinkat` and `openat` behave as
  the parser assumes.
* Cross-checked the `ReadProcessMemory` failure modes against public
  documentation/reports: a range that hits an inaccessible page, including a
  range in a target that has just exited, fails with `ERROR_PARTIAL_COPY` (299),
  not `ERROR_INVALID_HANDLE`.
* Three independent reviewers covered the Windows backend, the core API, and
  scans/exports/errors/tests. Every finding below was re-read in the source and
  either kept, merged, or downgraded; one reviewer claim (the instruction-cache
  test is a "liability") was rejected as compliant with the explicit AGENTS.md
  testing requirement.

### Gate status

| Check | Result |
|---|---|
| `just ci` (fmt, clippy host + Windows, tests, doctests, docs, Windows check/clippy) | **pass** |
| `cargo test --workspace --all-targets --release` | **pass** |
| `cargo check --target x86_64-unknown-linux-musl --all-targets` | **pass** |
| `cargo check --target i686-pc-windows-gnu --all-targets` | **pass** |
| `RUSTDOCFLAGS=-D warnings cargo doc --target x86_64-pc-windows-gnu` | **pass** |
| `cargo package --list` for all three crates | **pass** (README, both licenses, sources; no fixture/tests/`target/`) |
| Native Windows runtime tests | not run locally; covered by CI (Wine not used) |

The tree is in good shape. There are **no Critical findings**, no soundness
defect in the unsafe code, no reachable panic from untrusted input that I could
find, and the public contracts are mostly implemented carefully. The issues that
remain are identity/race problems, two documented behaviours that are not
delivered, a Windows concurrency hazard, and a set of documentation,
performance, and deduplication nits.

## Findings at a glance

| ID | Severity | Area | Finding |
|---|---|---|---|
| M1 | Major | Windows I/O + scans | A target exit during a Windows read/write is not classified as exit, so scans can swallow it and return "not found". |
| M2 | Major | Linux sys | `read_module_file` resolves `/proc/<pid>/root` by PID instead of the pinned proc-dir fd (violates the pinned-instance invariant). |
| M3 | Major | Strings | The documented "readable prefix at a mapping end" contract is not delivered for later chunks, and is impossible on Windows at all. |
| M4 | Major | Discovery | `open_by_name` does not bind enumeration identity to the opened handle; a same-name PID replacement is silently accepted. |
| M5 | Major | Windows write_code | Concurrent protection-changing calls can leave a page `PAGE_EXECUTE_READWRITE` after a call that returned an error, even for non-overlapping writes. |
| m1 | Minor | Model | A module's `size` is an address span, not its mappings; scans/`contains`/`ModuleMap::find` over-/under-approximate when a span has gaps or nesting. |
| m2 | Minor | Errors | `AddressSpaceReplaced` drops the sys error/source; module errors omit the PID (and parse errors the path); policy errors omit known address/length. |
| m3 | Minor | Docs | Several public `# Errors` sections omit variants the code returns (`ReadOnly`, `AddressSpaceReplaced`, `Allocation`, scan aborts); `read_value` docs are stale. |
| m4 | Minor | Module names | `module()`/module-scoped scans match case-sensitively and silently pick the first duplicate, while exports use platform rules and report ambiguity. |
| m5 | Minor | Windows exports | `read_module_file` has no file-identity check, and a target-controlled UNC/device path is opened in the caller's namespace (security note). |
| m6 | Minor | Windows errors | Module enumeration retries an exit as a module race; `ERROR_FILE_NOT_FOUND`/`PATH_NOT_FOUND` are classified `Other`; the nested retry loop's synthetic error drops the raw code. |
| m7 | Minor | Windows open | `open()` can succeed for an already-terminated process whose object still lingers; docs claim `NotFound` and Linux rejects zombies. |
| m8 | Minor | Windows discovery | Process enumeration can pair a Tool Help name with an image path from a different process instance under PID reuse. |
| m9 | Minor | Windows portability | The `IsWow64Process2` → `IsWow64Process` "older systems" fallback is unreachable when the export is missing (static import). |
| m10 | Minor | Performance | Scan chunks are zero-filled before every read; lists are sorted twice; Linux scans allocate paths they never use; per-module range rebuilds; `region_at`/`module_at` clone after building a full map. |
| m11 | Minor | Docs/skills | CHANGELOG `open_by_name` claim is inconsistent; README coverage claim is stronger than the suite; two skills have drifted. |
| m12 | Minor | Tests | Gaps: real adjacent-mapping scan, scan-after-exit, string later-chunk boundary, PE forwarders/ordinals, versioned ELF, direct snapshot APIs, end-to-end partial transfers. |
| n1–n19 | Nit | Various | See the nit list at the end (pattern limit check, token preview, dedup, preflight variant, `?`-inside-loop hardening, etc.). |

---

## Major findings

### M1 — Windows: target exit is not classified, so scans can return "not found"

**Locations:** `crates/memdiver-sys/src/windows.rs:227-229`, `windows.rs:260-262`,
`windows.rs:1286-1299`; `crates/memdiver-core/src/scan.rs:237-248`.

```rust
// windows.rs read()
if succeeded == 0 {
    return Err(last_error());          // ERROR_PARTIAL_COPY is classified Other
}
...
fn win_error(code: u32) -> Error {
    let kind = match code {
        ...
        ERROR_INVALID_HANDLE => ErrorKind::ProcessExited,
        _ => ErrorKind::Other,
    };
```

`ReadProcessMemory`/`WriteProcessMemory` against a target that has exited (or a
range that hits an inaccessible page) fail with `ERROR_PARTIAL_COPY` (299).
`win_error` leaves that as `ErrorKind::Other`, and `read`/`write` never check
liveness. `scan.rs` only treats `AddressSpaceReplaced` and
`Error::Read { source: ProcessExited }` as fatal, so if the target exits after
`scan_regions()` succeeded, every chunk read is skipped as "ordinary unreadable
memory" and `find_patterns`/`find_patterns_in_modules` can return `Ok(empty)` or
a partial result instead of aborting.

This violates AGENTS.md invariant 12 ("A replaced address space or an exited
process aborts the scan instead of being treated as 'not found'") and the README
promise in the Limitations section. It also means `Process::read`/`write` report
a generic OS error rather than a `ProcessExited`-classified source, and
`ErrorKind::InvalidAddress` is usually not produced for failed Windows *reads*
(`ReadProcessMemory` reports `ERROR_PARTIAL_COPY`); failing protection calls
such as `VirtualProtectEx` do surface `ERROR_INVALID_ADDRESS`. The
README's "matching the Windows `ERROR_INVALID_ADDRESS` class" is therefore
misleading for reads.

**Fix:** capture `last_error_code()` immediately, check
`WaitForSingleObject(handle, 0)` (i.e. `is_alive()`); if the target is gone,
return `ErrorKind::ProcessExited`. Otherwise map `ERROR_PARTIAL_COPY` and
`ERROR_INVALID_ADDRESS` to `ErrorKind::InvalidAddress` (keeping the raw code).
Apply to both `read` and `write`. Add a Windows test that kills the fixture
between region enumeration and a scan, and a unit test for the classification.

**Confidence:** high on the code gap; high that `PARTIAL_COPY` is the usual
failure after target close (documented publicly and reported by other tools).

### M2 — Linux: module files are resolved with a fresh `/proc/<pid>` lookup

**Locations:** `crates/memdiver-sys/src/linux.rs:392`,
`linux.rs:1075-1090` (and `linux.rs:366-407`).

```rust
let full_path = target_root_path(self.pid, path)?;   // builds /proc/{pid}/root/...
let file = File::open(&full_path).map_err(io_error)?;
```

`target_root_path(pid, path)` constructs `/proc/<pid>/root/<path>` from the PID
text, then `File::open` resolves it. The handle already owns a pinned
`/proc/<pid>` directory descriptor (`self.proc_dir`), and the skill explicitly
says "keep `/proc/<pid>` open ... Use `openat` relative to the directory
descriptor." If the target exits and its PID is reused between
`ensure_same_process()` (line 370) and the `File::open` (line 393), the lookup
can resolve in the *new* process's mount namespace. The inode check limits the
damage, but cross-filesystem inode reuse can still let a different file pass,
and even without reuse this violates AGENTS.md invariant 1 ("Never replace a
pinned operation with a fresh PID lookup") and the README claim "PID reuse cannot
redirect access". It also makes the claimed inode identity a race rather than a
pin.

**Fix:** open the file through the pinned descriptor, e.g. `openat(self.proc_dir,
"root/<relative>", O_RDONLY | O_CLOEXEC)` with a `CString` built from the
non-UTF-8 path bytes, then `fstat` the returned descriptor. (`openat` through the
proc-dir fd was verified to resolve `root/...` on this host.) Keep the inode
check. `target_root_path` can then be removed or become the string builder for
the `openat` path. Add a comment explaining why the fd, not the PID, is used.

**Confidence:** high (code inspection + pinned-fd experiment).

### M3 — Strings: the readable-prefix contract is not delivered for later chunks / Windows

**Locations:** `crates/memdiver-core/src/strings.rs:60-119` (`read_c_string_with`),
`strings.rs:121-189` (`read_utf16_string_with`), docs at `strings.rs:10-23` and
`strings.rs:40-52`; `crates/memdiver-sys/src/windows.rs:210-231`.

```rust
let filled = match read(current, &mut buffer[..chunk_len]) {
    Ok(()) => chunk_len,
    Err(Error::PartialRead { transferred, .. }) if transferred > 0 && transferred <= chunk_len => {
        transferred
    }
    Err(error) => return Err(error),   // a later chunk that is fully inaccessible
};
```

The public docs say a chunk run that crosses into inaccessible memory returns the
readable prefix, and the CHANGELOG says only a *first* chunk with a zero-byte
transfer must fail. In practice:

* A later chunk that starts in inaccessible memory returns
  `Error::Read`/`Error::PartialRead { transferred: 0 }`, which is propagated and
  the already-read prefix is discarded. This is common when an unterminated
  string ends exactly on a 256-byte chunk boundary (page-aligned mappings).
* On Windows, `ReadProcessMemory` fails with `ERROR_PARTIAL_COPY` when a chunk
  crosses an inaccessible page. The sys layer returns `Err(last_error())` and
  drops `lpNumberOfBytesRead`, so the core only sees `Error::Read`; the
  `PartialRead` arm never matches. The prefix fallback therefore never works on
  Windows, even when the terminator was in the readable part.

The unit test `c_string_without_terminator_returns_the_readable_prefix` only
covers a short *first* chunk, so this is invisible to the suite.

**Fix (choose one, and align docs):**
1. Structural: let the sys read report the transferred count alongside a failed
   transfer (still an error — do not infer success), and have the string helpers
   use the readable prefix on a later-chunk failure that is
   `InvalidAddress`/`PermissionDenied`/partial, while still propagating
   `ProcessExited`, `AddressSpaceReplaced`, `AddressRange`, and `Allocation`.
   Add a unit test with data whose length is an exact multiple of 256 followed by
   a failing chunk.
2. Narrower: document the prefix tolerance as Linux-only and only for a partial
   transfer in the current chunk; reword the docs and CHANGELOG accordingly.

**Confidence:** high on the Linux later-chunk behaviour; high on the Windows
mechanism (RPM fails on an inaccessible page).

### M4 — `open_by_name`: enumeration identity is not bound to the opened handle

**Locations:** `crates/memdiver-core/src/process.rs:178-215` (verification at
line 199), `crates/memdiver-core/src/process_info.rs:54-61`,
`crates/memdiver-core/src/process.rs:795-801`; sys: `linux.rs:505-523`.

```rust
let process = match Self::open_with(candidate.pid(), access) { ... };
if !verified_name(process.name()?.as_deref(), name) { continue; }
return Ok(process);
```

`find_by_name` returns `ProcessInfo { pid, name, exe_path }`; it carries no
start time (Linux) or creation time (Windows). `open_with` verifies that the PID
does not change *during the open*, but if the enumerated process exits after the
scan and its PID is reused by another process with the same image name, the open
succeeds and the image-name check passes. The caller receives a handle to a
different process instance while the docs say "a process that exits or is
replaced during the operation is retried ... before `ProcessChanged`". The
README's "PID reuse cannot redirect access" is therefore not true for the
enumeration→open window (it is true for an already-open handle).

Related inconsistency: `find_by_name` can match via `ProcessInfo::name`, which on
Linux falls back to `/proc/<pid>/comm` when `exe` is unreadable, but
`open_by_name` verifies only the executable basename (`Process::name()`). A
comm-only candidate can be found by `find_by_name` yet can never be opened;
the retry ends in `ProcessChanged` even though the process is stable.

**Fix:** carry a process identity token in `ProcessInfo` (Linux start time from
`/proc/<pid>/stat`; Windows `GetProcessTimes` creation time) and expose it on
`Process`/`ProcessHandle` (the Linux handle already stores `start_time`). Compare
the opened handle's identity with the candidate before returning it; continue
(retry) if they differ. Use one matching rule for discovery and verification
(image name only, or image name plus comm with a documented precedence), and
update the docs/CHANGELOG. A deterministic test is hard; a unit test for the
identity comparison plus a comment in the integration harness is sufficient.

**Confidence:** high on the behaviour; the same-name replacement is inherent to
name-only verification.

### M5 — Windows: concurrent protection-changing calls can leak RWX

**Locations:** `crates/memdiver-sys/src/windows.rs:328-388` (`write_code`),
`windows.rs:395-430` (`restore_pages`); `crates/memdiver-core/src/process.rs:58-61`
(thread-safety claim).

```rust
VirtualProtectEx(handle, page, page_size, PAGE_EXECUTE_READWRITE, &mut previous); // T1
...
self.write(address, buffer);
let (restore, ...) = self.restore_pages(&changed, page_size); // restores `previous`
```

`Process` is `Send + Sync` and only warns about overlapping *byte ranges*. Two
`write_code` calls on disjoint byte ranges that share a page (or a `protect`
concurrent with `write_code`) can interleave:

1. T1 records the page as RX and makes it RWX.
2. T2 records the page as RWX and makes it RWX.
3. T1 writes and restores RX.
4. T2's write fails (page no longer writable), then T2 restores its recorded
   "previous" RWX.

Both calls return; T2 reports a write failure, but the page is left RWX and no
restore failure is reported. That is a silent protection change under usage the
docs appear to permit (writes to non-overlapping ranges).

**Fix:** serialize protection-changing operations. A `Mutex<()>` in
`ProcessHandle` (or a private lock in `Process`) around `write_code`/`protect`
fixes the same-handle case; two independently opened `Process` handles to the
same target still race, so also document that concurrent protection changes for
the same page across handles are unsupported. Consider a `debug_assert` or a
comment that `restore_pages` must not be interleaved. A deterministic
multi-thread test is hard; at minimum document the page-granularity restriction
next to the existing overlapping-range warning.

**Confidence:** high on the interleaving; exposure requires concurrent code
patches on the same page, which the API currently does not forbid.

---

## Minor findings

### m1 — Module spans over/under-approximate module memory

**Locations:** `crates/memdiver-core/src/module.rs:55-72` (`size`, `contains`),
`module.rs:99-107` (`ModuleMap::find`), `crates/memdiver-core/src/scan.rs:206-235`
(`scan_ranges` clipping).

On Linux a module's `size` is the span from its lowest to its highest mapping
(per AGENTS.md), but the mappings can be non-contiguous. Any readable mapping
that happens to fall in a gap inside the span (another module, an injected
mapping) is included by `scan_ranges(regions, Some(module))`, so
`find_pattern_in_module` / `find_patterns_in_module` / `find_values_in_module`
can scan and return memory that does not belong to the named module. Conversely
`Module::contains` returns `true` for gap addresses, and `ModuleMap::find` checks
only the last module whose base is `<= address`, so if spans overlap it can miss
an enclosing module. Windows modules are contiguous `SizeOfImage` ranges, so this
is Linux-specific.

**Fix (choose one):** store the exact mapping intervals (or stable file identity)
in `RawModule`/`Module` and use them for `contains`, `ModuleMap::find`, and scan
clipping; or document explicitly that a module is its address span and that a
module-scoped scan covers all readable memory in that span. At minimum fix the
`Module::size`/`contains` docs and add a unit test for a module with a gap.

**Confidence:** high on the span semantics; occurrence requires an unusual
mapping layout (the construction is possible in principle by mapping a second file into the
unmapped gap between a library's segments with `MAP_FIXED`; I did not reproduce
it on the accessible sample processes, and one reviewer reported doing so).

### m2 — Error context/source gaps

**Locations:** `crates/memdiver-core/src/process.rs:466-480` and `482-496`
(`read_error`/`write_error` drop the sys error for `AddressSpaceReplaced`);
`crates/memdiver-core/src/error.rs:111-126` (`AddressSpaceReplaced` has no
`source`), `error.rs:251-282` (`ModuleFile` has module+path but no PID;
`ModuleExports`/`ModuleParse` have module but no path), `error.rs:174-181` /
`234-241` / `154-161` (`InvalidLength`, `ReadOnly`, `Unsupported` omit known
address/length).

`Error`'s docs say every OS failure keeps its `OsError` as a source, and
AGENTS.md invariant 4 requires process/address/length context where relevant.
`AddressSpaceReplaced` is constructed by dropping the sys `Error`; the source
chain ends. Module file/parse errors do not identify the target process (relevant
when the caller holds several handles), and parse errors do not carry the path.
Read-only rejection on a multi-entry write batch cannot name the offending
entry/range.

**Fix:** add `source: OsError` to `AddressSpaceReplaced` (construct it from the
sys error in all three mapping sites) or explicitly document why the synthetic
classification has no source and narrow the `Error` docs. Add `pid` to the
`Module*` variants (and `path` to `ModuleParse`). Consider adding pid/address/len
to `ReadOnly`/`InvalidLength`/`Unsupported` constructions, at least for
`protect` and single-entry writes, or explain in the docs that these are policy
errors that intentionally omit the range.

**Confidence:** high.

### m3 — Public docs omit returned variants (and one is stale)

**Locations:** `crates/memdiver-core/src/process.rs:331-338` (`write` omits
`ReadOnly`), `579-581` (`write_value` delegates to `write`, so it also returns
`ReadOnly`), `745-751` (`protect` omits `ReadOnly`), `389-402` (`write_code` omits
`AddressSpaceReplaced`), `543-560` (`read_value` says "same errors as
`read_bytes`", including `Allocation`, but it never allocates);
`crates/memdiver-core/src/batch.rs:12-14` (`read_many` omits `Allocation`);
`crates/memdiver-core/src/scan.rs:23-25`, `46-49` (`find_pattern`/
`find_pattern_in_module` omit `Allocation` and the mid-scan abort variants);
`scan.rs:77-80`, `106-109`, `136-139` (list enumeration/allocation but not
`AddressSpaceReplaced`/`ProcessExited`).

`read_value`'s implementation reads directly into `T` with no heap buffer
(`process.rs:565-570`), so the docs' "copied out of an unaligned byte buffer"
and `Allocation` error are outdated. The `# Errors` sections should name every
variant the operation can return, including the read-only rejection, the
address-space-replaced abort, and allocation failures.

**Fix:** update the `# Errors` lists and the `read_value` prose; mention the
zero-length/read-only precedence explicitly (it is a contract, not an
implementation detail).

**Confidence:** high.

### m4 — Module name resolution is inconsistent across the API

**Locations:** `crates/memdiver-core/src/process.rs:713-727` (`module`) and
`crates/memdiver-core/src/scan.rs:55-57`, `146-148` (module-scoped scans) versus
`crates/memdiver-core/src/exports.rs:133-155` (`find_module_for_exports` /
`unique_module`).

`Process::module` compares names exactly, including case, and returns the first
match in load order; scans accept the same `&str` and use that resolver. Exports
use `name_matches` (ASCII case-insensitive on Windows) and return
`Error::AmbiguousModuleName` when several modules match. With duplicate
basenames (two directories, or a deleted mapping plus its replacement on Linux)
the scan silently targets one module while exports refuse to choose; on Windows,
`find_pattern_in_module("KERNEL32.DLL")` fails while
`module_exports("KERNEL32.DLL")` works. The docs for `module` warn about case but
not about ambiguity.

**Fix:** share one resolver: platform-aware matching, plus an explicit ambiguity
error (a new `find_unique_module`/`module_exports`-style method, or a
`Result<Option<Module>>` for `module`). Add `*_of(&Module)` scan variants, as
already done for exports, so callers can target one snapshot unambiguously.
Update the docs either way.

**Confidence:** high (the code is unambiguous; this is an API consistency
decision).

### m5 — Windows module-file access has no identity check and opens target-controlled paths

**Locations:** `crates/memdiver-sys/src/windows.rs:681-694`; compare
`linux.rs:366-407` (inode check).

```rust
let present = modules.iter().any(|module| module.base == base && module.path == path);
...
let file = File::open(path).map_err(io_error)?;
```

On Windows, `read_module_file` only checks that a module with the same base and
path is still listed, then opens `path`. Unlike Linux, there is no inode/file-ID
check, so a module file replaced on disk at the same path is parsed silently
(the rebased addresses are still bounded by the live image, but export names and
RVAs can be wrong). Additionally, `path` comes from `GetModuleFileNameExW` and is
opened in the *caller's* namespace. A target can load a DLL from a UNC path
(`\\attacker\share\x.dll`); the inspecting process will then contact that share
(and may send NTLM authentication), which is a credential-exposure risk when the
inspector is more privileged than the target. A device path is also opened
before `read_bounded_file` rejects it as non-regular.

**Fix:** verify the opened file's identity against the module (file ID or
volume serial + file index via `GetFileInformationByHandle`, or at least size and
PE image header/`SizeOfImage` consistency). Reject UNC (`\\`) and device
(`\\.\`) prefixes before opening, or require an explicit opt-in for non-local
paths; document the caller-namespace risk in the README (it currently only says
"the path is opened in the caller's namespace").

**Confidence:** high on behaviour; the UNC risk is real but requires a malicious
target and export resolution to be requested.

### m6 — Windows error classification and retry details

**Locations:** `windows.rs:650-667` + `1084-1094` + `1100-1106` (module retries),
`windows.rs:1279-1284` (`io_error`), `windows.rs:773-814` (nested retries),
`windows.rs:451-484` (preflight variant).

* If the process exits during module enumeration, `ERROR_INVALID_HANDLE` /
  `ERROR_PARTIAL_COPY` is treated as a module-unload race and retried up to 8
  times; on exhaustion the error kind is `NotFound`/`Other`, not
  `ProcessExited`, so `Process::modules()` reports a misleading `Enumerate`
  source and wastes full enumerations.
* `std::io::Error` from opening a missing module file carries
  `ERROR_FILE_NOT_FOUND` (2) or `ERROR_PATH_NOT_FOUND` (3); `win_error` maps both
  to `Other`, while Linux maps `ENOENT` to `NotFound`. This is a platform
  parity/diagnostic gap.
* `modules_once` has an inner retry loop (for buffer-size races) inside
  `modules()`'s outer retry loop, so up to 64 full enumerations; when the size
  race persists, the exhaustion error is a fresh `Error` with no raw code,
  losing the last OS error.
* `ensure_range_committed` reports preflight failures through
  `CodeWriteFailure::Protect { address, len }`, but the sys docs describe
  `Protect` as "the page whose protection could not be changed"; the reported
  address/len are the first offending byte and the remaining range, not a page.
  Core then surfaces `Error::Protect` for a query failure.

**Fix:** check `is_alive()` before retrying/returning a retryable module error
and return a `ProcessExited`-classified error when the process is gone; map
Win32 file-not-found codes to `NotFound` in `io_error`/`win_error`; collapse the
nested retry loops and preserve the last OS error/raw code in the exhaustion
error; add a preflight-specific `CodeWriteFailure`/`Error` variant or document
the address/len semantics precisely.

**Confidence:** high.

### m7 — Windows `open()` can return a handle to an already-terminated process

**Locations:** `crates/memdiver-sys/src/windows.rs:89-139` (no liveness check);
docs at `windows.rs:91-93`; `crates/memdiver-core/src/process.rs:89-95`.

```rust
let handle = unsafe { OpenProcess(access, 0, pid) };
if handle.is_null() { ... }
Ok(Self { pid, handle: OwnedHandle::new(handle) })
```

Windows keeps the process object (and its PID) alive while any handle is open.
`OpenProcess` can therefore succeed for a terminated process whose PID lingers;
the returned handle is signaled, memory/region/module operations fail, and
`is_alive()` is false (metadata queries such as `exe_path` may still succeed). The sys docs claim `ErrorKind::NotFound` "for ... a process that has
already exited"; the core docs claim `ProcessNotFound` "when the process does
not exist". Linux, by contrast, rejects zombies at open (`is_dead_state`). This
is a parity and documentation defect; `open_by_name` can also return a dead
handle through this path.

**Fix:** after a successful `OpenProcess`, call `WaitForSingleObject(handle, 0)`;
if it is signaled, close the handle and return a `ProcessExited`-classified
error (core maps it to `Error::Open`; alternatively add a distinct variant).
Narrow the docs to "invalid PID" for `NotFound` and mention that a process can
exit immediately after a successful open (inherent race).

**Confidence:** high on the Windows behaviour (documented by multiple sources);
the race window is small.

### m8 — Windows process enumeration can pair metadata from two instances

**Locations:** `windows.rs:935-944`.

```rust
let name = wide_to_string(&entry.szExeFile);
let exe_path = limited_image_path(pid, &mut path_buffer);
```

The Tool Help name is captured at snapshot time; the image path is queried
through a fresh `OpenProcess` by PID. If the PID is reused in between, the entry
can combine the old process's name with the new process's path.
`ProcessInfo::matches_name` checks both, so `find_by_name` can surface
inconsistent metadata (though `open_by_name` re-verifies after opening).

**Fix:** when `exe_path` is available, derive the name from its file name and use
the Tool Help name only as a fallback (Linux already prefers the executable
name). Document that enumeration metadata is a best-effort snapshot.

**Confidence:** high on the code; occurrence is a narrow race.

### m9 — `IsWow64Process2` fallback claim is not reachable on old Windows

**Locations:** `windows.rs:157-185`; README line 349; AGENTS.md.

`windows_sys::link!("kernel32.dll" ... IsWow64Process2)` is a static import.
On systems predating Windows 10 1709 the image fails to load with "entry point
not found"; the `IsWow64Process` fallback never executes there. The fallback only
helps if the export exists but the call fails. The README's "falling back to
`IsWow64Process` on older systems" is inaccurate.

**Fix:** state the minimum supported Windows version (Windows 10 1709+ for the
unconditional import), or resolve `IsWow64Process2` dynamically with
`GetProcAddress` if older systems must load the binary. Keep the call-failure
fallback and reword the docs.

**Confidence:** high on linkage; project relevance depends on the support matrix.

### m10 — Performance opportunities (hot paths)

1. **Scanner zero-fill (biggest).** `scan.rs:302-303`:
   `buffer.clear(); buffer.resize(want, 0);` zero-fills the entire chunk every
   iteration before the OS read overwrites it — up to ~2 MiB of extra writes per
   chunk (roughly doubling memory traffic). Resize once to `max_buffer_len`
   before the loop, then `read` into `&mut buffer[..want]`; do not `clear()`.
   (The buffer must stay initialized for safe `&mut [u8]`, so a single initial
   allocation/zero-fill is fine; repeated zeroing is not.)
2. **Double sorting.** The Linux backend sorts maps (`linux.rs:885`), the Windows
   backend sorts regions (`windows.rs:635`) and modules (`windows.rs:802-806`),
   and core sorts again (`process.rs:617`, `649`, `685`). Sort once; the Windows
   module sort is required for `regions_with_paths`'s binary search, the others
   are not. This is O(n log n) per call on every region/module query.
3. **Linux path allocation in path-free scans.** `regions_without_paths` is
   just `regions()` on Linux (`linux.rs:325-327`), so every scan allocates a
   `PathBuf` per file-backed mapping and drops it. Add a parse mode that skips
   the pathname column (still parse the fields) for `regions_without_paths`;
   Windows already has the equivalent path-free path.
4. **Per-module range rebuilds.** `find_pattern` and `find_patterns_in_modules`
   call `scan_module` per module, and `scan_module` calls
   `scan_ranges(regions, Some(module))`, which walks all regions for every module
   (O(modules × regions)) and allocates a fresh range `Vec` each time. Build a
   module→ranges map once (or index regions by module bounds) and reuse one
   scratch buffer across ranges.
5. **`region_at`/`module_at`.** They build a full `RegionMap`/`ModuleMap` and
   then clone the found entry (`process.rs:661-663`, `709-711`), including
   `PathBuf`/`String`. Use `self.regions()?.into_iter().find(|r| r.contains(a))`
   for the one-shot case; keep the map APIs for repeated lookups.
6. **Windows `exe_path`.** `query_image_path` allocates a fresh 64 KiB buffer per
   call (`windows.rs:982-985`); process enumeration already reuses one. Reuse a
   buffer or start small and grow.
7. **Infallible scan scratch growth.** `scan_ranges` pushes without
   `try_reserve`, `scan_regions` uses `collect`; the docs promise
   `Error::Allocation` for output growth. Make scratch growth fallible or narrow
   the docs.
8. **No-anchor patterns.** A pattern with no fully-fixed byte (`?? ??`, `A? ?B`)
   has `anchor() == None`; `scan_buffer` then runs `matches_at` at every byte
   (`scan.rs:334-349`). For a pattern near the 1 MiB limit this is quadratic.
   Add a fast path for all-wildcard patterns (every aligned start is a hit) or
   document the cost; add a unit test for the `None` branch.
9. **String chunk size.** 256-byte chunks mean many syscalls for long strings.
   Consider a larger chunk (page-aware) while keeping the partial-prefix
   behavior; `read_c_string_lossy` also copies valid UTF-8 unnecessarily
   (`from_utf8_lossy(...).into_owned()`); `String::from_utf8(bytes)` can move the
   buffer and fall back to lossy decoding only on invalid input.

### m11 — Documentation and skills drift

* **CHANGELOG** says "An unreadable name is treated as unverified and the bounded
  retry ends in `Error::ProcessChanged`" but the next sentence says Windows
  executable-path failures are errors; in code, `process.name()?` propagates
  `Error::Query` on Windows, and only `Ok(None)` leads to retry/`ProcessChanged`.
  Reword to distinguish "name unavailable (`Ok(None)`)" from "query failed".
* **README** claim "every operation is covered by unit or real cross-process
  integration tests" is stronger than the suite (see m12); "PID-reuse safety" is
  covered by a Linux unit test of the start-time check, not end-to-end; the
  `region_map`/`module_map` methods are exercised indirectly.
* **Skills.** `.dsh/skills/memdiver-platform-backends/SKILL.md` still says
  "Pointer width uses `IsWow64Process`" (code and AGENTS use
  `IsWow64Process2`), its contract list omits `read_module_file` and
  `regions_without_paths`, and its module-retry list omits
  `ERROR_INVALID_HANDLE` (AGENTS and code include it).
  `.dsh/skills/memdiver-integration-testing/SKILL.md` omits the `ZERO` and
  `EXEC` fixture commands and says to use the test executable's unique name for
  open-by-name, while the harness actually uses a uniquely named *fixture copy*.
  AGENTS.md's review checklist explicitly asks for skill drift checks.

**Fix:** update these documents after deciding M4/M9/m5.

**Confidence:** high.

### m12 — Test-coverage gaps

| Gap | Where | Why it matters |
|---|---|---|
| Real adjacent-mapping scan | `scanning.rs`, `scan.rs:206-235` | Coalescing has unit tests but no end-to-end mapping pair; a pattern crossing a real mapping boundary is untested. |
| Scan after target exit (Windows) | `system.rs`, `scan.rs:242-248` | M1 is exactly the case the suite does not exercise. |
| String later chunk starting in inaccessible memory | `navigation.rs`, `strings.rs` | M3's behaviour is unit-tested only for a partial first chunk. |
| Direct `Process::region_map`/`module_map` | `queries.rs` | Public API added in 0.2.0; only exercised via `region_at`/`module_at` and direct map unit tests. |
| End-to-end `PartialRead`/`PartialWrite` | `read_write.rs` | Linux can produce a real short read at a mapping end (verified with `pread`); Windows partial-with-failure is an error by design, but the contract should be documented/tested. |
| PE forwarders / ordinal-only exports | `system.rs`, `exports.rs` tests | Only helper-level tests; a real or synthetic PE export table with a forwarder/ordinal would catch a regression. |
| Versioned ELF / `versym` | `exports.rs` tests | Version preference is unit-tested with a synthetic map, not a real versioned module. |
| `find_patterns_in_modules` aggregation/limit across modules | `scanning.rs` | Only exercised indirectly via `find_values_in_modules`. |
| Windows page size | `queries.rs:183-184` | Hardcodes `0xfff`/`0x1000`; use `GetSystemInfo` page size in the fixture target (the fixture already exposes it for `MULTI`). |
| Restored bytes after `protect` | `queries.rs:233` | `read_bytes(...).is_ok()` only proves readability; compare with the expected pattern. |

---

## Nits (low priority)

1. `pattern.rs:37-62` — the in-loop `bytes.len() == MAX_PATTERN_LEN` check makes the
   post-loop `bytes.len() > MAX_PATTERN_LEN` check unreachable; keep one check and
   add exact-limit tests (MAX accepted, MAX+1 rejected). The test currently only
   covers MAX+1.
2. `pattern.rs:119-127` — `token_preview` truncates by chars but appends `...`
   based on byte length; a 20-char non-ASCII token (40 bytes) gets a spurious
   ellipsis. Base the ellipsis on the chars actually dropped.
3. `windows.rs:1202-1211` — `timeout_millis` does `try_from(...).unwrap_or(MAX-1).min(MAX-1)`;
   both arms clamp, so the `min` is redundant. `millis.min(u128::from(u32::MAX - 1))
   as u32` is clearer.
4. `windows.rs:307-313`, `316-326`, `332-338`, `451-455`, `458-466`, `469-475`,
   `1164-1168` — seven copies of
   `CodeWriteError::Failed(CodeWriteFailure::Protect { ... })`;
   add a `protect_failure(address, len, source)` helper and split the preflight.
5. `windows.rs:328-338` — the `?` for the page-address computation is inside the
   mutation loop; if it ever fired, earlier pages would stay RWX because
   `restore_pages` is skipped. It is unreachable today (page_count bounds it), but
   compute all page addresses before mutating, or restore on this branch.
6. `windows.rs:451-484` — preflight failures use the `Protect` variant with a
   non-page address/len; see m6.
7. `windows.rs:552-556` — `self.modules().unwrap_or_default()` swallows
   module-enumeration errors (including process exit) and silently leaves region
   paths `None`; documented as best-effort, but a ProcessExited here should
   probably propagate or be documented more precisely.
8. `windows.rs:1123-1137` — `wide_to_os_string`/`wide_to_string` duplicate the
   NUL scan; one helper over `[u16]` plus a conversion choice is enough.
9. `linux.rs:841-843` — `.nth(18)` for the start time has no explanatory comment
   (the field index is easy to get wrong); add "state is field 3, starttime is
   field 22, so skip 18 tokens after the state token".
10. `linux.rs:305-312`, `341-347`, `366-370` — three copies of
    `ensure_same_process` + `read_proc_file(MAPS)` + `parse_maps` +
    `ensure_same_process`; factor into one `maps_snapshot()` helper.
11. `process.rs:466-496` and `803-837` — `read_error`/`write_error` and
    `ensure_complete_read`/`ensure_complete_write` are near-duplicates; a shared
    helper (or a small `Transfer` enum) reduces drift.
12. `region.rs:115-149` and `module.rs:86-120` — near-identical sorted-range maps;
    a generic `RangeMap<T>` would prevent the divergence that led to m1.
13. `scan.rs:271` and `326` — `pattern_len == 0` is impossible through the public
    API (`Pattern` constructors reject empty); either remove the checks or make
    `Pattern::len`/`is_empty` the single source of truth.
14. `address.rs:37-50` — `match ... { Some(v) => Some(Self(v)), None => None }` is
    `self.0.checked_add(offset).map(Self)`.
15. `batch.rs:12-14` — `read_many` can return `Error::Allocation` for its result
    vector but the docs only mention `BatchRead`; see m3.
16. `common/mod.rs:314-321` — after `EXEC` the re-exec'd fixture prints a second
    `READY` line that `exec()` never consumes; any later `peek`/`ping` would read
    it as a response. `exec()` should receive/validate the new `READY` and update
    `address`/`len`, or mark the fixture stale.
17. `common/mod.rs:116-132` + `376-381` — `spawn_unique` leaks the copied fixture
    binary if `spawn_from` fails (abort_child only kills/joins). Remove the copy
    on all failure paths (cleanup guard).
18. `queries.rs:183-184` — hardcoded 4 KiB page; use the fixture's reported page
    size (see m12).
19. `system.rs:150-163` — the Windows privilege test accepts `Ok(())` without
    verifying the token; a stub returning `Ok` would pass on elevated CI. This is
    hard to verify without test-only OS code; add a comment or verify
    `AdjustTokenPrivileges`/`TOKEN_PRIVILEGES` state if practical.

---

## Verified sound (selected)

* **Unsafe audit.** Every `unsafe` block in `linux.rs`/`windows.rs` has a
  `SAFETY` comment (11/11 and 35/35). All pointers and lengths passed to
  `readlinkat`, `openat`, `pread64`, `pwrite64`, `poll`, `OpenProcess`,
  `IsWow64Process2`, `Read/WriteProcessMemory`, `VirtualQueryEx`,
  `VirtualProtectEx`, `EnumProcessModulesEx`, `GetModuleInformation`,
  `GetModuleFileNameExW`, `QueryFullProcessImageNameW`, the Tool Help calls,
  `GetSystemInfo`, and the token calls are valid for the documented lengths.
  `GetLastError` is captured immediately at every failure site; every handle is
  checked for its sentinel and closed exactly once by `OwnedHandle`; no handle
  wrapper is `Copy`. `Send + Sync` follows from the stored `File`/`usize` state.
  Integer conversions are checked `u64 → i64` on Linux and `u64 → usize` on
  Windows; no unguarded slicing in non-test code.
* **Handle/resource lifetime.** Linux `proc_dir`/`mem`/pidfd and every temporary
  `File` close on all error paths; Windows `OpenProcess`,
  `CreateToolhelp32Snapshot`, `OpenProcessToken`, and the temporary
  enumeration handles have RAII wrappers and no leaks. `Drop` never terminates
  the target.
* **Scanner arithmetic.** The chunk/overlap/step logic and the anchor search
  were exhaustively modelled (see Method); no missed or duplicate matches. The
  hit limit, alignment on absolute addresses, guard/unreadable skipping, and
  fatal-error propagation on Linux are correct. `max_results = 0` maps to
  unlimited and the loops stop exactly at the limit.
* **Pattern parser.** Wildcard/nibble masks, lone `?`, case-insensitive hex,
  size limits, and error previews are correct and panic-free; `from_exact_bytes`
  rejects zero-sized values.
* **Strings.** Terminator handling, UTF-16 unit framing, odd partial transfers,
  surrogate replacement, zero limits, and `max_bytes`/`max_units` bounds are
  correct; the only issue is the documented prefix contract (M3).
* **Exports.** ELF/PE selection, goblin error sources, `ET_DYN`/`ET_EXEC`
  rebasing, live-range bounds, PE forwarder/ordinal skipping, version preference
  via `versym`, and `MAX_MODULE_FILE_SIZE` are implemented as specified. The
  deliberate exclusion of `SHN_ABS` version-definition symbols is sensible
  (those are not real exports); document it if desired.
* **Transfers and typed I/O.** Zero-length no-ops, overflow rejection before OS
  calls, short-transfer errors with both counts, `Pod`-only unaligned access,
  and batch entry indices with full sources are correct. Read-only rejection
  happens before any OS call for `write`/`write_code`/`write_value`/`protect`
  (and before any entry of `write_many`), while zero-length writes remain no-ops.
* **Linux exec detection.** Zero-byte transfers are classified as
  `AddressSpaceReplaced` for a live process and `ProcessExited` for a dead one;
  reads, writes, `write_code`, and scans propagate it (Linux). Verified the
  `/proc/<pid>/mem` zero-read behaviour on this host.
* **Windows `write_code` (single-threaded).** Per-page raw protection capture,
  restore on every path, composite errors, committed-range preflight, and the
  no-`FlushInstructionCache` limitation are implemented as specified.
* **Public surface.** `#[non_exhaustive]` on `Error`/`ErrorKind`/`RegionKind`/
  `ProcessAccess`; `missing_docs` denied; no printing/logging in library code;
  no `unsafe` in `memdiver`/`memdiver-core`; package contents and licenses are
  correct.

## Considered and not reported as defects

* The cfg-gated instruction-cache tests (`process.rs:865-877`) are tautologies,
  but AGENTS.md explicitly requires "a cfg-gated test that pins the documented
  architecture condition". They satisfy that requirement; the comment already
  explains why a behavioural test is impossible.
* `ReadProcessMemory` copying a partial buffer and failing is surfaced as
  `Error::Read` rather than `PartialRead`; AGENTS.md's Windows note explicitly
  requires the call to be an error and forbids inferring success from a byte
  count. Only the string-prefix contract (M3) fails because the count is
  discarded.
* The `CodeWriteError::Failed(CodeWriteFailure::Protect)` conversion of
  `ensure_range_committed` failures is documented at the core level ("not fully
  committed" -> `Error::Protect`); only the sys-level doc wording needs work
  (m6).
* `Process::protect` returning the first page's protection for a multi-page range
  is explicitly documented and warned about; `write_code` is the safe path.
* The `SHN_ABS`/`st_value == 0` ELF exclusions are conservative and exclude
  version-definition symbols; not treating them as exports is correct for the
  documented symbol classes.

## Suggested priority

1. **M1** (Windows exit classification + scan abort) — invariant 12 violation,
   can turn a dead process into an empty scan.
2. **M2** (Linux pinned module-file lookup) — identity/pinning invariant, small
   patch.
3. **M5** (Windows protection race) — silent protection change; at minimum
   document, ideally serialize.
4. **M3** (string prefix contract) — docs vs behaviour; decide and implement.
5. **M4** (open-by-name identity) — the headline PID-reuse guarantee; needs an
   identity token in `ProcessInfo`.
6. **m1/m2/m3/m4** — API/model/error-context/documentation correctness.
7. **m10** — performance, starting with the scan zero-fill.
8. **m6–m9, m11, m12, nits** — classification, docs, tests, cleanup.

---

## Resolution (2026-11-09)

Every finding above was addressed in commits `ff73ab1..243c282` on `main`:

| Finding | Commit(s) |
|---|---|
| M1 Windows exit classification | `ff73ab1` |
| M2 pinned Linux module-file lookup | `a0fa8f9` |
| M5 protection serialization | `780dd8c` |
| M3 partial transfers / string prefix | `b678480` |
| M4 open-by-name identity | `1245a52` |
| m1 exact module mappings | `294089c` |
| m2 error source/context | `47da5f0` |
| m3 error docs | `400368e` |
| m4 module-name resolution | `54aa921` |
| m5 Windows module path/PE identity | `0559eea` |
| m6 Windows classification/retries | `10d6ea1` |
| m7 Windows dead-process open | `ed345b7` |
| m8 name/path from one instance | `1245a52` |
| m9 IsWow64Process2 docs | `9052c32` |
| m10 performance | `7421d90` |
| m11 docs/skills | `5b0f7e3` |
| m12 tests | `52a8427`, `fb1615d` |
| nits | `fb87d6d`, `cc31306`, `243c282` |

Deliberate deviations:

* `Error::Unsupported` remains context-free by design (a platform-capability
  error, documented in the variant).
* The `pattern_len == 0` guards in the scan helpers are retained as defensive
  checks for an internal invariant.
* The nested module-enumeration retry loops are retained (bounded, now
  liveness-checked); collapsing them would add state for a cold race path.
* `Address::checked_add` keeps the `match` form because `Option::map` is not
  const-callable on the 1.85 MSRV.
* Native Windows runtime tests were not available locally; the Windows-only
  tests are compiled and linted for `x86_64-pc-windows-gnu` and run in CI.

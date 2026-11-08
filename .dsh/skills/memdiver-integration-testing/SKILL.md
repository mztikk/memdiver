---
name: memdiver-integration-testing
description: Use when adding or debugging end-to-end tests for memdiver, extending the memdiver-fixture protocol, or when the Linux ptrace / Windows access path prevents a test from running.
---

# End-to-end testing

Read [AGENTS.md](../../../AGENTS.md) and the
`memdiver-platform-backends` skill first. End-to-end tests live in
`crates/memdiver-integration-tests` and use only the public `memdiver` API.

## Layout

```text
crates/memdiver-integration-tests/
  src/bin/memdiver-fixture.rs   deterministic child process + module signature
  tests/common/mod.rs           handshake, fixture, signature constant
  tests/read_write.rs           bytes, typed values, errors, concurrency
  tests/write_code.rs           scoped code writes, read-only rejection, protection restore
  tests/queries.rs              regions, modules, protection, module_at
  tests/process_selection.rs    process list, by-name open, read-only access
  tests/scanning.rs             module/heap scans, wildcards, alignment, limits
  tests/navigation.rs           pointer width/chains, bounded C/UTF-16 strings
  tests/system.rs               wait-for-exit, privilege helper, module exports
  tests/lifecycle.rs            liveness, open failures, dead-process I/O
```

The fixture binary is a target of the same package, so Cargo provides
`CARGO_BIN_EXE_memdiver-fixture` to the integration tests. `Fixture::spawn()`
starts it with piped stdin/stdout, parses the first line, opens it with
`Process::open`, and kills it on drop. Never hand-roll another child-process
harness.

## Fixture protocol

The child allocates a deterministic 4096-byte heap buffer and prints:

```text
READY <pid> <address> <length>
```

Then it reads one command per line and writes one response line:

| Command | Response |
|---------|----------|
| `PING` | `PONG` |
| `PEEK <offset> <length>` | lowercase hex bytes |
| `CODE` | `CODE <address> <length>` for the executable code target |
| `EXIT` | exits |

Invalid commands or ranges produce `ERR`. The child is blocked on stdin while
the parent accesses its memory, so the two processes never touch the buffer
concurrently. Preserve that property: do not add commands that read the buffer
spontaneously or on a timer.

The pattern is `byte[i] = (i * 37 + 11) mod 256`; `common::pattern` and the
fixture both implement it. Keep them in sync.

The fixture executable also contains `MODULE_SIGNATURE`, a fixed 16-byte
sequence in read-only data. `common::module_signature_text()` formats it as a
scan pattern. Keep the fixture and `common` constants byte-identical; module
scans rely on it being in an image section.

`CODE` exposes `code_target`, a never-called function in the executable image,
plus `CODE_LEN` (currently 4). The parent must only write the function's existing
bytes back through `write_code`; patching different instruction bytes risks
crashing the fixture if a protection restore ever fails. `common::CODE_LEN` must
stay in sync with the fixture.

## Writing a test

* Use `Fixture::spawn()` and access `fixture.process`, `fixture.address`, and
  `fixture.len`.
* Verify write results from the child's point of view with
  `fixture.peek(offset, len)`; also read them back through the API when useful.
* Assert structured error variants, not only messages; check `source()` when
  the test is about OS error preservation.
* Do not assert exact whole lists of regions or modules. Assert sortedness,
  membership, and containment.
* Use `fixture.kill()` for lifecycle tests; the `Drop` implementation will not
  panic if the child is already gone.
* Tests run in parallel and each owns a separate fixture process. Never share
  mutable global state between tests.
* Concurrency tests: reads may overlap freely; writes must target disjoint
  byte ranges. Wrap a separately opened `Process` in `Arc` to share it; the
  fixture keeps its own handle.
* Process-name tests must not assume the fixture name is unique: other tests
  spawn fixtures concurrently. Use the test executable's unique name for a
  successful `open_by_name` test, and two fixtures for an ambiguity test.
* Read-only tests must read successfully and assert `Error::ReadOnly` for
  `write`, `write_code`, `write_value`, and `protect`. Zero-length writes,
  including `write_code`, remain no-ops.
* `write_code` tests cover the fixture heap, zero-length no-ops, read-only
  rejection, and overflowing ranges. The Windows test uses `fixture.code_target()`
  to confirm the address is executable and non-writable, writes its existing
  bytes with `write_code`, and asserts the region's protection is identical
  afterwards. Do not rely on a plain `write` failing on that page: Wine and other
  compatibility layers may not enforce the page protection for
  `WriteProcessMemory`, so the `VirtualQueryEx`-reported protection is the
  authoritative check in the test.
* Composite restore-error construction cannot be forced reliably through the OS;
  cover its formatting and source chain with a unit test in `memdiver-core` and
  document why.
* Scan tests need a module-resident signature (`MODULE_SIGNATURE`), a heap-only
  signature that `find_pattern` must not return, wildcard/nibble cases,
  alignment, result limits, and a unit test for a match spanning the scan-chunk
  boundary.
* Pointer tests must honor `PointerWidth` (write `u32` or `u64` accordingly),
  check empty chains, and cover width-specific overflow. String tests cover
  truncation, lossy decoding, unpaired surrogates, and multi-chunk reads.
* Value tests write a unique value into the heap, assert all-memory scan finds
  it, assert module scans do not, and assert zero-sized values are rejected.
* Batch tests cover ordered reads/writes, empty batches, entry-index errors with
  the underlying error preserved, and read-only rejection for non-empty writes.
* Wait tests use a second handle in a thread, kill the fixture after a short
  delay, and assert timeout-then-exit behavior and immediate return after death.
* Privilege tests are platform-gated: Linux asserts `Unsupported`; Windows
  accepts success or a structured `Error::Privilege`.
* Export tests resolve a real libc export on Linux and an ntdll export on
  Windows, assert the address is inside the module, and verify name lookup.
* Windows-only tests go behind `#[cfg(windows)]`. Linux-only tests, such as the
  `protect` `Unsupported` case, go behind `#[cfg(target_os = "linux")]`.
* Use `Address::checked_add` for addresses. Test overflow and zero-length
  contracts explicitly.
* Use `#[cfg(test)]` unit tests in `memdiver-sys` for parsing and permission
  translation; do not require a live process for those.

## Running and debugging

```sh
cargo test -p memdiver-integration-tests --all-targets
cargo test -p memdiver-integration-tests --test read_write -- --nocapture
cargo test --workspace --all-targets
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
# Optional local Windows execution when Wine is installed:
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine \
  WINEPREFIX=$PWD/.wine-test \
  cargo test -p memdiver-integration-tests --test write_code --target x86_64-pc-windows-gnu
```

If a fixture test fails before any assertion:

1. Run with `--nocapture`; the fixture inherits stderr.
2. Check `cat /proc/sys/kernel/yama/ptrace_scope` on Linux. The library needs
   descendant access or `CAP_SYS_PTRACE`; the fixture is a descendant, so
   normal CI and developer shells work.
3. Check that the test is not running inside a sandbox that hides `/proc` or
   blocks `/proc/<pid>/mem` (`hidepid=2`, seccomp, dropped capabilities).
4. On Windows, run the test from an elevated terminal when inspecting another
   elevated process; the fixture is a child, so no elevation is normally
   needed.
5. Do not mark a failing test `#[ignore]`. Fix the implementation or document
   why the platform cannot support the operation and assert the appropriate
   `Error::Unsupported` instead.

## Quality gate

The full sequence before committing is in the `memdiver-review-gate` skill. At
minimum, run the host test suite, clippy for the host and Windows target, and
the Windows cross-check. Windows-only tests can be exercised locally under Wine
as a debugging aid; that is not a replacement for native Windows CI. Compile
them locally with `--all-targets` so type errors and lint violations do not
reach CI.

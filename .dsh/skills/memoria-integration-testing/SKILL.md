---
name: memoria-integration-testing
description: Use when adding or debugging end-to-end tests for memoria, extending the memoria-fixture protocol, or when the Linux ptrace / Windows access path prevents a test from running.
---

# End-to-end testing

Read [AGENTS.md](../../../AGENTS.md) and the
`memoria-platform-backends` skill first. End-to-end tests live in
`crates/memoria-integration-tests` and use only the public `memoria` API.

## Layout

```text
crates/memoria-integration-tests/
  src/bin/memoria-fixture.rs   deterministic child process
  tests/common/mod.rs          handshake + command harness
  tests/read_write.rs          bytes, typed values, errors, concurrency
  tests/queries.rs             regions, modules, protection
  tests/lifecycle.rs           liveness, open failures, dead-process I/O
```

The fixture binary is a target of the same package, so Cargo provides
`CARGO_BIN_EXE_memoria-fixture` to the integration tests. `Fixture::spawn()`
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
| `EXIT` | exits |

Invalid commands or ranges produce `ERR`. The child is blocked on stdin while
the parent accesses its memory, so the two processes never touch the buffer
concurrently. Preserve that property: do not add commands that read the buffer
spontaneously or on a timer.

The pattern is `byte[i] = (i * 37 + 11) mod 256`; `common::pattern` and the
fixture both implement it. Keep them in sync.

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
* Windows-only tests go behind `#[cfg(windows)]`. Linux-only tests, such as the
  `protect` `Unsupported` case, go behind `#[cfg(target_os = "linux")]`.
* Use `Address::checked_add` for addresses. Test overflow and zero-length
  contracts explicitly.
* Use `#[cfg(test)]` unit tests in `memoria-sys` for parsing and permission
  translation; do not require a live process for those.

## Running and debugging

```sh
cargo test -p memoria-integration-tests --all-targets
cargo test -p memoria-integration-tests --test read_write -- --nocapture
cargo test --workspace --all-targets
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
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

The full sequence before committing is in the `memoria-review-gate` skill. At
minimum, run the host test suite, clippy for the host and Windows target, and
the Windows cross-check. Windows-only tests are executed by CI; compile them
locally with `--all-targets` so type errors and lint violations do not reach CI.

---
name: memdiver-review-gate
description: Use before every memdiver commit, push, or release to run the full quality gate, perform the required code review, and verify the tree is clean.
---

# Review gate before committing

The repository rules require a code review before every commit and a passing
test suite on the exact tree being committed. This skill is the executable
checklist.

## 1. Inspect the diff

```sh
git status --short
git diff
git diff --staged
```

Read the entire diff, not just the summary. Look for:

* debug leftovers (`dbg!`, `println!` in libraries, commented-out code),
* unrelated edits, generated files, or accidental `.dsh/state` changes,
* public API changes without docs, changelog/matrix updates,
* new `unsafe` without a `// SAFETY:` comment,
* new tests that cannot fail or that assert only that a call returns.

## 2. Run the gate

```sh
just fmt-check
just clippy
just test
just doc-test
just doc
just windows-check
just windows-clippy
```

`just check` runs the host commands above; `just ci` adds the Windows checks.
The Windows binaries can additionally be exercised under Wine on Linux when a
prefix and the MinGW target are available; this is a local aid, not a
replacement for native Windows CI. All commands
must pass without warnings. If the Windows target is missing, install it with
`rustup target add x86_64-pc-windows-gnu`. Never commit with a failing gate; if a
check truly cannot run, say so in the commit body.

Tests must run on the final tree after formatting and any last-second edits.
Re-run the gate after every change, including documentation-only changes that
touch code examples.

## 3. Review the invariants

* **Pinned process:** Linux uses the procfs descriptors plus start time; Windows
  uses the kernel handle for every query, including modules. No PID-only
  fallback was introduced.
* **No panic on input:** every public path returns `Result`; malformed procfs
  data, bad addresses, overflow, and partial transfers are errors.
* **No truncation:** short OS transfers surface as `PartialRead` /
  `PartialWrite` with both counts.
* **Error context:** process, address, and length are present where relevant;
  the `OsError` source and raw code are preserved.
* **Typed access:** only `Pod`; unaligned copies; zero-sized values handled.
* **Read-only access:** write, write_code, and protect paths reject
  `ProcessAccess::ReadOnly` before touching the OS; zero-length writes remain
  no-ops.
* **Scoped code writes:** `write_code` protects each page covering the range,
  records raw per-page protection, restores every changed page on every exit
  path, and reports both the write/protection failure and any restore failure.
  It must never return success with a page still modified, and it must not rely
  on `protect`'s first-page return for a multi-page range. Linux skips the
  protection step and writes through `/proc/<pid>/mem`.
* **Process discovery:** name matching uses platform case rules, ambiguous names
  return candidates, and the opened process is verified against its image name.
* **Scanning:** chunks overlap by `pattern.len() - 1`, unreadable/guard regions
  are skipped, results are bounded, and `find_pattern` is module-scoped while
  `find_patterns` is all-memory. Value scans use exact native bytes and reject
  zero-sized values.
* **Batching:** failures identify the entry index and preserve the full inner
  error; read-only handles reject non-empty write batches before writing.
* **Waiting/privileges:** Linux waits on a verified pidfd and falls back to
  polling only when pidfd is unavailable; timeouts do not report exit, and
  privilege enabling is opt-in, never automatic.
* **Exports:** parsed from the module file with `goblin`; forwarders/ordinals are
  skipped, addresses are rebased and bounded to the live module.
* **Platform parity:** the README matrix and docs match the implementation;
  unsupported operations return `Unsupported`, never fake success.
* **Resources:** every handle/descriptor closes exactly once on success and
  error paths; no leaked Windows snapshot handles.
* **Concurrency:** `Process` remains `Send + Sync`; no shared mutable state in
  the library; writes to overlapping ranges are the caller's responsibility.
* **Unsafe:** re-audit each block for pointer validity, length validity, checked
  conversions, ownership, and `Send`/`Sync` implications.

## 4. Verify tests are meaningful

* Pure logic has unit tests next to it, including boundaries and malformed
  input.
* Platform behaviour has a fixture-based test through the public API.
* New error paths assert the structured variant and, where relevant, the source
  error. Composite scoped-write errors must retain both failures and their
  address/range context; if a restore failure cannot be forced through the OS,
  check for a focused unit test of its construction/formatting.
* Platform-specific branches have a test or a documented reason why they can
  only run in CI.
* Run the release profile once when touching concurrency or overflow-sensitive
  code: `cargo test --workspace --all-targets --release`.

## 5. Package sanity

```sh
cargo package --list --allow-dirty -p memdiver-sys
cargo package --list --allow-dirty -p memdiver-core
cargo package --list --allow-dirty -p memdiver
```

The package must contain the source, README, license files and license
metadata, and must not contain the fixture, integration tests, or `target/`.
Internal `path + version` dependencies cannot be verified against the registry
before the lower crate is published; `--list` is the pre-commit check, full
`cargo package` verification is a publish-time check. Note any skipped check in
the commit.

## 6. Commit and push

* Stage explicitly (`git add -A` after reviewing `git status`; never stage
  `target/`).
* Use a focused conventional commit:
  `feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`, `perf:`.
  Explain *why* in the body; mention any check that could not run.
* Confirm `git diff --cached` contains exactly the intended change.
* Commit (signing is the maintainer's configuration) and push the branch.
* After pushing, check CI status when available. Do not claim a release or
  platform result that CI has not produced.

## Definition of done

A change is done when the diff is reviewed, every gate passes, the tests prove
the new behaviour, documentation/matrix are updated, and the commit is pushed.

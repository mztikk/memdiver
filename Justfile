set shell := ["bash", "-euo", "pipefail", "-c"]

default := "check"

# Format all crates in place.
fmt:
    cargo fmt --all

# Fail when formatting is not canonical.
fmt-check:
    cargo fmt --all -- --check

# Lint every target with warnings denied.
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run unit, integration, and fixture tests.
test:
    cargo test --workspace --all-targets --all-features

# Run documentation tests (the examples in rustdoc comments).
doc-test:
    cargo test --workspace --doc --all-features

# Build API documentation with warnings denied.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# Everything that must pass on the host before a commit.
check: fmt-check clippy test doc-test doc

# Type-check every target of the Windows backend from a non-Windows host.
windows-check:
    cargo check --workspace --all-targets --all-features --target x86_64-pc-windows-gnu

# Lint every target of the Windows backend from a non-Windows host.
windows-clippy:
    cargo clippy --workspace --all-targets --all-features --target x86_64-pc-windows-gnu -- -D warnings

# The complete local gate, including the Windows cross-checks.
ci: check windows-check windows-clippy

# Build all crates and test targets.
build:
    cargo build --workspace --all-targets --all-features

# Run the process inspection example.
example:
    cargo run -p memdiver --example inspect

# Run the self-read example.
example-self:
    cargo run -p memdiver --example read_self

# List the files that would be packaged for each library crate.
package:
    cargo package --list --allow-dirty -p memdiver-sys
    cargo package --list --allow-dirty -p memdiver-core
    cargo package --list --allow-dirty -p memdiver

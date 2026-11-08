//! End-to-end tests for scoped code writes.
#![allow(missing_docs, unreachable_pub)]

mod common;

use common::{Fixture, pattern};
use memdiver::{Address, Error, Process};

#[test]
fn writes_code_to_the_fixture_heap() {
    let mut fixture = Fixture::spawn();
    let offset = 100;
    let address = fixture.address.checked_add(offset as u64).unwrap();
    let payload = vec![0x5A; 32];
    let expected = pattern(fixture.len);

    fixture
        .process
        .write_code(address, &payload)
        .expect("scoped code write");
    assert_eq!(fixture.peek(offset, payload.len()), payload);
    assert_eq!(
        fixture
            .process
            .read_bytes(address, payload.len())
            .expect("read back"),
        payload
    );

    let observed = fixture.peek_all();
    assert_eq!(&observed[..offset], &expected[..offset]);
    assert_eq!(
        &observed[offset + payload.len()..],
        &expected[offset + payload.len()..]
    );
}

#[test]
fn zero_length_code_writes_are_no_ops() {
    let mut fixture = Fixture::spawn();
    let before = fixture.peek_all();

    fixture
        .process
        .write_code(Address::NULL, &[])
        .expect("zero-length write is a no-op");

    assert_eq!(fixture.peek_all(), before);
}

#[test]
fn read_only_handles_reject_non_empty_code_writes() {
    let mut fixture = Fixture::spawn();
    let before = fixture.peek_all();
    let readonly = Process::open_readonly(fixture.process.pid()).expect("read-only open");

    let error = readonly
        .write_code(fixture.address, b"nope")
        .expect_err("read-only code write must fail");
    match error {
        Error::ReadOnly { pid, operation } => {
            assert_eq!(pid, fixture.process.pid());
            assert_eq!(operation, "Process::write_code");
        }
        other => panic!("unexpected {other:?}"),
    }

    readonly
        .write_code(fixture.address, &[])
        .expect("zero-length write is a no-op");
    assert_eq!(fixture.peek_all(), before);
}

#[test]
fn rejects_overflowing_code_write_ranges_without_an_os_call() {
    let fixture = Fixture::spawn();
    let error = fixture
        .process
        .write_code(Address::new(u64::MAX), b"x")
        .expect_err("overflowing range must fail");
    assert!(
        matches!(error, Error::AddressRange { .. }),
        "unexpected {error:?}"
    );
}

#[cfg(windows)]
#[test]
fn writes_to_read_only_executable_code_and_restores_protection() {
    let mut fixture = Fixture::spawn();
    let (address, len) = fixture.code_target();
    let region = fixture
        .process
        .region_at(address)
        .expect("region query")
        .expect("code target must be inside a committed region");
    assert!(
        region.is_executable(),
        "code target is not executable: {region:?}"
    );
    assert!(
        !region.is_writable(),
        "code target must start non-writable: {region:?}"
    );

    let original = fixture
        .process
        .read_bytes(address, len)
        .expect("read code target");
    // The OS-reported protection is the authoritative check that the page is
    // not writable. Native Windows also rejects a plain WriteProcessMemory to
    // such a page, but compatibility layers may not enforce that, so the test
    // does not depend on the plain-write failure.
    fixture
        .process
        .write_code(address, &original)
        .expect("scoped code write to an executable, non-writable page");
    assert_eq!(
        fixture
            .process
            .read_bytes(address, len)
            .expect("read patched code target"),
        original
    );

    let restored = fixture
        .process
        .region_at(address)
        .expect("region query")
        .expect("code target region after write");
    assert_eq!(
        restored.protection(),
        region.protection(),
        "the original protection must be restored"
    );
    assert!(restored.is_executable());
    assert!(!restored.is_writable());

    fixture.ping();
}

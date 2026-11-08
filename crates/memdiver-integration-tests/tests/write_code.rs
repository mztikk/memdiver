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

#[cfg(target_os = "linux")]
#[test]
fn writes_existing_bytes_to_read_only_executable_code_on_linux() {
    let mut fixture = Fixture::spawn();
    let (address, len) = fixture.code_target();
    let region = fixture
        .process
        .region_at(address)
        .expect("region query")
        .expect("code target must be inside a committed region");
    assert!(region.is_executable(), "{region:?}");
    assert!(!region.is_writable(), "{region:?}");

    let original = fixture
        .process
        .read_bytes(address, len)
        .expect("read code target");
    fixture
        .process
        .write_code(address, &original)
        .expect("scoped code write through /proc/<pid>/mem");
    assert_eq!(
        fixture
            .process
            .read_bytes(address, len)
            .expect("read code target after write"),
        original
    );
    fixture.ping();
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

#[cfg(windows)]
#[test]
fn unaligned_multi_page_code_write_restores_both_pages() {
    let mut fixture = Fixture::spawn();
    let target = fixture.multi_page_target();
    let address = target.address.checked_add(1).expect("unaligned start");
    let len = target.len.checked_sub(2).expect("range fits");
    let second_address = target
        .address
        .checked_add(target.page_size as u64)
        .expect("second page address");

    let first_before = fixture
        .process
        .region_at(target.address)
        .expect("first page region")
        .expect("first page mapped");
    let second_before = fixture
        .process
        .region_at(second_address)
        .expect("second page region")
        .expect("second page mapped");

    let original = fixture
        .process
        .read_bytes(address, len)
        .expect("read unaligned multi-page range");
    fixture
        .process
        .write_code(address, &original)
        .expect("unaligned multi-page code write");
    assert_eq!(
        fixture
            .process
            .read_bytes(address, len)
            .expect("read range after write"),
        original
    );

    let first_after = fixture
        .process
        .region_at(target.address)
        .expect("first page region after write")
        .expect("first page still mapped");
    let second_after = fixture
        .process
        .region_at(second_address)
        .expect("second page region after write")
        .expect("second page still mapped");
    assert_eq!(first_after.protection(), first_before.protection());
    assert_eq!(second_after.protection(), second_before.protection());
}

#[cfg(windows)]
#[test]
fn multi_page_code_write_restores_differing_protections() {
    let mut fixture = Fixture::spawn();
    let target = fixture.multi_page_target();
    assert_eq!(
        target.address.get() % target.page_size as u64,
        0,
        "multi-page target must be page-aligned"
    );
    let second_address = target
        .address
        .checked_add(target.page_size as u64)
        .expect("second page address");

    let first_before = fixture
        .process
        .region_at(target.address)
        .expect("first page region query")
        .expect("first page must be inside a committed region");
    let second_before = fixture
        .process
        .region_at(second_address)
        .expect("second page region query")
        .expect("second page must be inside a committed region");
    assert!(first_before.is_readable(), "{first_before:?}");
    assert!(first_before.is_executable(), "{first_before:?}");
    assert!(!first_before.is_writable(), "{first_before:?}");
    assert!(second_before.is_readable(), "{second_before:?}");
    assert!(!second_before.is_executable(), "{second_before:?}");
    assert!(!second_before.is_writable(), "{second_before:?}");
    assert_ne!(
        first_before.protection(),
        second_before.protection(),
        "the two pages must start with different protections"
    );

    let original = fixture
        .process
        .read_bytes(target.address, target.len)
        .expect("read multi-page target");
    fixture
        .process
        .write_code(target.address, &original)
        .expect("scoped code write across two pages");
    assert_eq!(
        fixture
            .process
            .read_bytes(target.address, target.len)
            .expect("read multi-page target after write"),
        original
    );

    let first_after = fixture
        .process
        .region_at(target.address)
        .expect("first page region query after write")
        .expect("first page must still be inside a committed region");
    let second_after = fixture
        .process
        .region_at(second_address)
        .expect("second page region query after write")
        .expect("second page must still be inside a committed region");
    assert_eq!(
        first_after.protection(),
        first_before.protection(),
        "the first page's original protection must be restored"
    );
    assert_eq!(
        second_after.protection(),
        second_before.protection(),
        "the second page's original protection must be restored"
    );

    fixture.ping();
}

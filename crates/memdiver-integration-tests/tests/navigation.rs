//! End-to-end tests for pointer chains and bounded string reads.
#![allow(missing_docs, unreachable_pub)]

mod common;

use common::Fixture;
use memdiver::{Address, Error, PointerWidth, Process};

fn write_pointer(
    process: &Process,
    address: Address,
    value: Address,
    width: PointerWidth,
) -> Result<(), Error> {
    match width {
        PointerWidth::Bits32 => {
            process.write_value(address, u32::try_from(value.get()).expect("32-bit pointer"))
        }
        PointerWidth::Bits64 => process.write_value(address, value.get()),
    }
}

#[cfg(target_pointer_width = "64")]
const NATIVE_WIDTH: PointerWidth = PointerWidth::Bits64;
#[cfg(target_pointer_width = "32")]
const NATIVE_WIDTH: PointerWidth = PointerWidth::Bits32;

#[test]
fn detects_pointer_width_and_resolves_chains() {
    let fixture = Fixture::spawn();
    let width = fixture.process.pointer_width().expect("pointer width");
    assert_eq!(width, NATIVE_WIDTH);

    let base = fixture.address.checked_add(0x100).expect("base");
    let first = fixture.address.checked_add(0x200).expect("first");
    let second = fixture.address.checked_add(0x300).expect("second");
    write_pointer(&fixture.process, base, first, width).expect("write first pointer");
    write_pointer(
        &fixture.process,
        first.checked_add(0x8).expect("first slot"),
        second,
        width,
    )
    .expect("write second pointer");

    assert_eq!(
        fixture
            .process
            .read_pointer(base, width)
            .expect("read pointer"),
        first
    );
    let resolved = fixture
        .process
        .resolve_pointer_chain(base, &[0x8, 0x10], width)
        .expect("resolve chain");
    assert_eq!(
        resolved,
        second.checked_add(0x10).expect("expected address")
    );

    // The resolved address is inside the fixture buffer and readable.
    let _: u32 = fixture.process.read_value(resolved).expect("read resolved");
    assert_eq!(
        fixture
            .process
            .resolve_pointer_chain(base, &[], width)
            .expect("empty chain"),
        base
    );
}

#[test]
fn pointer_chain_overflow_is_reported() {
    let fixture = Fixture::spawn();
    let width = fixture.process.pointer_width().expect("pointer width");
    let slot = fixture.address.checked_add(0x700).expect("slot");
    let oversized = match width {
        PointerWidth::Bits32 => Address::new(u64::from(u32::MAX)),
        PointerWidth::Bits64 => Address::new(u64::MAX),
    };
    write_pointer(&fixture.process, slot, oversized, width).expect("write pointer");

    let error = fixture
        .process
        .resolve_pointer_chain(slot, &[1], width)
        .expect_err("must overflow");
    assert!(
        matches!(error, Error::PointerChainOverflow { .. }),
        "unexpected {error:?}"
    );
}

#[test]
fn reads_bounded_c_strings() {
    let fixture = Fixture::spawn();
    let address = fixture.address.checked_add(0x800).expect("address");
    fixture
        .process
        .write(address, b"memdiver\0trailing")
        .expect("write string");

    assert_eq!(
        fixture
            .process
            .read_c_string(address, 64)
            .expect("read c string"),
        b"memdiver"
    );
    assert_eq!(
        fixture
            .process
            .read_c_string_lossy(address, 64)
            .expect("read lossy"),
        "memdiver"
    );
    assert_eq!(
        fixture
            .process
            .read_c_string(address, 3)
            .expect("truncated"),
        b"mem"
    );
    assert!(
        fixture
            .process
            .read_c_string(Address::NULL, 0)
            .expect("zero max")
            .is_empty()
    );

    let no_nul = fixture.address.checked_add(0x900).expect("address");
    fixture
        .process
        .write(no_nul, b"abcde")
        .expect("write unterminated string");
    assert_eq!(
        fixture
            .process
            .read_c_string(no_nul, 5)
            .expect("bounded read"),
        b"abcde"
    );

    let invalid = fixture.address.checked_add(0x940).expect("address");
    fixture
        .process
        .write(invalid, &[0xFF, 0xFE, 0x00])
        .expect("write invalid utf8");
    assert_eq!(
        fixture
            .process
            .read_c_string(invalid, 8)
            .expect("raw bytes"),
        [0xFF, 0xFE]
    );
    assert_eq!(
        fixture
            .process
            .read_c_string_lossy(invalid, 8)
            .expect("lossy"),
        "\u{fffd}\u{fffd}"
    );

    let error = fixture
        .process
        .read_c_string(Address::new(u64::MAX), 4)
        .expect_err("overflow");
    assert!(
        matches!(error, Error::AddressRange { .. }),
        "unexpected {error:?}"
    );
}

#[test]
fn reads_bounded_utf16_strings() {
    let fixture = Fixture::spawn();
    let address = fixture.address.checked_add(0xA00).expect("address");
    let text = "héllo 🦀";
    let mut encoded = Vec::new();
    for unit in text.encode_utf16() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    encoded.extend_from_slice(&0u16.to_le_bytes());
    fixture
        .process
        .write(address, &encoded)
        .expect("write utf16 string");

    assert_eq!(
        fixture
            .process
            .read_utf16_string(address, 32)
            .expect("read utf16"),
        text
    );
    assert_eq!(
        fixture
            .process
            .read_utf16_string(address, 2)
            .expect("truncated utf16"),
        "hé"
    );
    assert!(
        fixture
            .process
            .read_utf16_string(Address::NULL, 0)
            .expect("zero max")
            .is_empty()
    );

    let terminated = fixture.address.checked_add(0xB00).expect("address");
    let mut short = Vec::new();
    for unit in "ab\0cd".encode_utf16() {
        short.extend_from_slice(&unit.to_le_bytes());
    }
    fixture
        .process
        .write(terminated, &short)
        .expect("write terminated string");
    assert_eq!(
        fixture
            .process
            .read_utf16_string(terminated, 16)
            .expect("read terminated"),
        "ab"
    );

    let unpaired = fixture.address.checked_add(0xB40).expect("address");
    let raw = [0x00, 0xD8, 0x00, 0x00];
    fixture
        .process
        .write(unpaired, &raw)
        .expect("write unpaired surrogate");
    assert_eq!(
        fixture
            .process
            .read_utf16_string(unpaired, 8)
            .expect("lossy utf16"),
        "\u{fffd}"
    );

    let error = fixture
        .process
        .read_utf16_string(Address::new(u64::MAX), 4)
        .expect_err("overflow");
    assert!(
        matches!(error, Error::AddressRange { .. }),
        "unexpected {error:?}"
    );
}

#[test]
fn long_strings_span_read_chunks() {
    let fixture = Fixture::spawn();

    let c_address = fixture.address.checked_add(0xC00).expect("address");
    let mut long = vec![b'x'; 1000];
    long.push(0);
    fixture
        .process
        .write(c_address, &long)
        .expect("write long c string");
    assert_eq!(
        fixture
            .process
            .read_c_string(c_address, 2000)
            .expect("read long c string"),
        vec![b'x'; 1000]
    );

    let utf16_address = fixture.address.checked_add(0x400).expect("address");
    let mut utf16 = Vec::new();
    for _ in 0..300 {
        utf16.extend_from_slice(&u16::from(b'a').to_le_bytes());
    }
    utf16.extend_from_slice(&0u16.to_le_bytes());
    fixture
        .process
        .write(utf16_address, &utf16)
        .expect("write long utf16 string");
    assert_eq!(
        fixture
            .process
            .read_utf16_string(utf16_address, 400)
            .expect("read long utf16 string"),
        "a".repeat(300)
    );
}

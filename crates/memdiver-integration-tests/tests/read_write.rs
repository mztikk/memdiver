//! End-to-end tests for the memdiver public API.
#![allow(missing_docs, unreachable_pub)]

mod common;

use std::sync::Arc;
use std::thread;

use common::{Fixture, pattern};
use memdiver::{Address, Error, Process};

#[test]
fn reads_entire_buffer_two_ways() {
    let mut fixture = Fixture::spawn();
    let expected = pattern(fixture.len);

    let mut buffer = vec![0u8; fixture.len];
    fixture.process.read(fixture.address, &mut buffer).unwrap();
    assert_eq!(buffer, expected);

    let bytes = fixture
        .process
        .read_bytes(fixture.address, fixture.len)
        .unwrap();
    assert_eq!(bytes, expected);

    assert_eq!(fixture.peek_all(), expected);
}

#[test]
fn reads_subranges_and_unaligned_typed_values() {
    let fixture = Fixture::spawn();
    let expected = pattern(fixture.len);

    let bytes = fixture
        .process
        .read_bytes(fixture.address.checked_add(17).unwrap(), 64)
        .unwrap();
    assert_eq!(bytes, &expected[17..81]);

    let unaligned = fixture.address.checked_add(1).unwrap();
    let value: u32 = fixture.process.read_value(unaligned).unwrap();
    assert_eq!(value.to_ne_bytes(), &expected[1..5]);

    let array: [u8; 8] = fixture
        .process
        .read_value(fixture.address.checked_add(9).unwrap())
        .unwrap();
    assert_eq!(array, expected[9..17]);
}

#[test]
fn writes_are_visible_to_the_target_process() {
    let mut fixture = Fixture::spawn();
    let expected = pattern(fixture.len);
    let payload: Vec<u8> = (0..200u16).map(|value| (value % 251) as u8).collect();
    let address = fixture.address.checked_add(100).unwrap();

    fixture.process.write(address, &payload).unwrap();
    assert_eq!(fixture.peek(100, payload.len()), payload);
    assert_eq!(
        fixture.process.read_bytes(address, payload.len()).unwrap(),
        payload
    );

    let observed = fixture.peek_all();
    assert_eq!(&observed[..100], &expected[..100]);
    assert_eq!(&observed[300..], &expected[300..]);
}

#[test]
fn typed_values_round_trip_through_the_target() {
    let mut fixture = Fixture::spawn();
    let address = fixture.address.checked_add(128).unwrap();

    let first = 0xDEAD_BEEF_CAFE_F00D_u64;
    fixture.process.write_value(address, first).unwrap();
    assert_eq!(fixture.process.read_value::<u64>(address).unwrap(), first);
    assert_eq!(fixture.peek(128, 8), first.to_ne_bytes());

    let second = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    fixture.process.write_value(address, second).unwrap();
    assert_eq!(
        fixture.process.read_value::<[u8; 16]>(address).unwrap(),
        second
    );
    assert_eq!(fixture.peek(128, 16), second);

    let float = std::hint::black_box(3.5f64);
    fixture.process.write_value(address, float).unwrap();
    assert_eq!(fixture.process.read_value::<f64>(address).unwrap(), float);
}

#[test]
fn zero_length_operations_do_not_touch_the_target() {
    let mut fixture = Fixture::spawn();
    let before = fixture.peek_all();

    let mut empty = [];
    fixture.process.read(Address::NULL, &mut empty).unwrap();
    fixture.process.write(Address::NULL, &[]).unwrap();
    assert!(
        fixture
            .process
            .read_bytes(Address::NULL, 0)
            .unwrap()
            .is_empty()
    );
    fixture
        .process
        .write_value(Address::NULL, [0u8; 0])
        .unwrap();

    assert_eq!(fixture.peek_all(), before);
}

#[test]
fn rejects_overflowing_ranges_without_an_os_call() {
    let fixture = Fixture::spawn();
    let address = Address::new(u64::MAX - 1);

    let mut buffer = [0u8; 8];
    let error = fixture
        .process
        .read(address, &mut buffer)
        .expect_err("must fail");
    assert!(
        matches!(error, Error::AddressRange { .. }),
        "unexpected {error:?}"
    );

    let error = fixture
        .process
        .write(address, &buffer)
        .expect_err("must fail");
    assert!(
        matches!(error, Error::AddressRange { .. }),
        "unexpected {error:?}"
    );

    let error = fixture
        .process
        .read_bytes(address, 8)
        .expect_err("must fail");
    assert!(
        matches!(error, Error::AddressRange { .. }),
        "unexpected {error:?}"
    );
}

#[test]
fn reports_allocation_failure_for_impossible_buffers() {
    let fixture = Fixture::spawn();
    let error = fixture
        .process
        .read_bytes(Address::NULL, usize::MAX)
        .expect_err("an impossible buffer size must fail");
    assert!(
        matches!(error, Error::Allocation { .. }),
        "unexpected {error:?}"
    );
}

#[test]
fn reports_unmapped_reads_and_writes_with_context() {
    use std::error::Error as _;

    let fixture = Fixture::spawn();
    let unmapped = Address::new(1);

    let error = fixture
        .process
        .read_bytes(unmapped, 16)
        .expect_err("address 1 must not be readable");
    assert!(matches!(error, Error::Read { .. }), "unexpected {error:?}");
    let message = error.to_string();
    assert!(message.contains("process"), "{message}");
    assert!(message.contains("0x1"), "{message}");
    assert!(message.contains("16 bytes"), "{message}");
    assert!(error.source().is_some(), "OS error must be preserved");

    let error = fixture
        .process
        .write(unmapped, b"should fail")
        .expect_err("address 1 must not be writable");
    assert!(matches!(error, Error::Write { .. }), "unexpected {error:?}");
    assert!(error.source().is_some(), "OS error must be preserved");
}

#[test]
fn works_concurrently_from_multiple_threads() {
    let mut fixture = Fixture::spawn();
    let process = Arc::new(Process::open(fixture.process.pid()).unwrap());
    let address = fixture.address;

    let readers: Vec<_> = (0..8)
        .map(|_| {
            let process = Arc::clone(&process);
            thread::spawn(move || {
                let expected = pattern(256);
                for _ in 0..50 {
                    let bytes = process.read_bytes(address, expected.len()).unwrap();
                    assert_eq!(bytes, expected);
                }
            })
        })
        .collect();
    for reader in readers {
        reader.join().expect("reader thread");
    }

    let writers: Vec<_> = (0..8u8)
        .map(|index| {
            let process = Arc::clone(&process);
            thread::spawn(move || {
                let payload = vec![index; 64];
                let offset = 64 + u64::from(index) * 128;
                process
                    .write(address.checked_add(offset).unwrap(), &payload)
                    .unwrap();
            })
        })
        .collect();
    for writer in writers {
        writer.join().expect("writer thread");
    }

    for index in 0..8u8 {
        let offset = 64 + usize::from(index) * 128;
        assert_eq!(fixture.peek(offset, 64), vec![index; 64]);
    }
}

#[test]
fn batch_reads_and_writes_work_in_order() {
    let mut fixture = Fixture::spawn();
    let expected = pattern(fixture.len);
    let first = fixture.address;
    let second = fixture.address.checked_add(64).expect("address");

    let results = fixture
        .process
        .read_many(&[(first, 8), (second, 16)])
        .expect("batch read");
    assert_eq!(
        results,
        vec![expected[..8].to_vec(), expected[64..80].to_vec()]
    );

    let payload_a = [0xAA; 8];
    let payload_b = [0xBB; 16];
    fixture
        .process
        .write_many(&[(first, &payload_a), (second, &payload_b)])
        .expect("batch write");
    assert_eq!(fixture.peek(0, 8), payload_a);
    assert_eq!(fixture.peek(64, 16), payload_b);

    assert!(
        fixture
            .process
            .read_many(&[])
            .expect("empty read batch")
            .is_empty()
    );
    fixture.process.write_many(&[]).expect("empty write batch");
}

#[test]
fn batch_errors_identify_the_failing_entry() {
    let fixture = Fixture::spawn();
    let bad = Address::new(u64::MAX);
    let error = fixture
        .process
        .read_many(&[(fixture.address, 8), (bad, 8)])
        .expect_err("batch read must fail");
    match error {
        Error::BatchRead {
            index,
            address,
            source,
            ..
        } => {
            assert_eq!(index, 1);
            assert_eq!(address, bad);
            assert!(matches!(*source, Error::AddressRange { .. }));
        }
        other => panic!("unexpected {other:?}"),
    }

    let error = fixture
        .process
        .write_many(&[(fixture.address, b"ok"), (bad, b"no")])
        .expect_err("batch write must fail");
    match error {
        Error::BatchWrite { index, source, .. } => {
            assert_eq!(index, 1);
            assert!(matches!(*source, Error::AddressRange { .. }));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn read_only_batch_writes_are_rejected() {
    let fixture = Fixture::spawn();
    let readonly = Process::open_readonly(fixture.process.pid()).expect("read-only open");
    let error = readonly
        .write_many(&[(fixture.address, b"nope")])
        .expect_err("read-only batch write must fail");
    assert!(
        matches!(error, Error::ReadOnly { .. }),
        "unexpected {error:?}"
    );
    readonly
        .write_many(&[(fixture.address, b"")])
        .expect("zero-length batch write is a no-op");
}

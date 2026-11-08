//! End-to-end tests for the memoria public API.
#![allow(missing_docs, unreachable_pub)]

mod common;

use common::Fixture;
use memoria::{Error, Process};

#[test]
fn handle_reflects_the_process_lifecycle() {
    let mut fixture = Fixture::spawn();
    let pid = fixture.process.pid();
    assert_eq!(pid, fixture.process.pid());
    assert!(fixture.process.is_alive());
    assert!(format!("{:?}", fixture.process).contains(&pid.to_string()));
    fixture.ping();

    fixture.kill();
    assert!(
        !fixture.process.is_alive(),
        "killed fixture must not be alive"
    );

    let error = fixture
        .process
        .regions()
        .expect_err("region query on a dead process must fail");
    assert!(
        matches!(error, Error::Enumerate { .. }),
        "unexpected {error:?}"
    );

    let mut buffer = [0u8; 4];
    let error = fixture
        .process
        .read(fixture.address, &mut buffer)
        .expect_err("reading a dead process must fail");
    assert!(
        matches!(error, Error::Read { .. } | Error::PartialRead { .. }),
        "unexpected {error:?}"
    );

    let error = fixture
        .process
        .write(fixture.address, b"dead")
        .expect_err("writing a dead process must fail");
    assert!(
        matches!(error, Error::Write { .. } | Error::PartialWrite { .. }),
        "unexpected {error:?}"
    );
}

#[test]
fn opening_a_nonexistent_process_reports_not_found() {
    let error = Process::open(u32::MAX).expect_err("PID u32::MAX must not exist");
    assert!(
        matches!(error, Error::ProcessNotFound { .. }),
        "unexpected {error:?}"
    );
    assert!(error.to_string().contains("4294967295"));
}

#[test]
fn self_access_works_and_matches_regions() {
    let process = Process::open(std::process::id()).expect("open self");
    let marker = std::hint::black_box(0x1234_5678_9abc_def0u64);
    let address = memoria::Address::new((&marker as *const u64) as u64);

    assert_eq!(process.read_value::<u64>(address).unwrap(), marker);
    let region = process
        .region_at(address)
        .expect("region query")
        .expect("stack must be mapped");
    assert!(region.contains(address));
    assert!(region.is_readable());

    assert!(!process.modules().expect("self modules").is_empty());
    assert!(process.is_alive());
}

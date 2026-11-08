//! End-to-end tests for process discovery, name matching, and access levels.
#![allow(missing_docs, unreachable_pub)]

mod common;

use std::path::Path;

use common::{Fixture, fixture_name};
use memdiver::{Error, Process, ProcessAccess, Protection};

#[test]
fn lists_processes_and_opens_the_current_process_by_name() {
    let executable = std::env::current_exe().expect("current executable");
    let expected_name = executable
        .file_name()
        .expect("test executable has a name")
        .to_string_lossy()
        .into_owned();

    let processes = Process::list().expect("process list");
    assert!(
        processes
            .windows(2)
            .all(|pair| pair[0].pid() <= pair[1].pid()),
        "process list must be sorted by PID"
    );
    let current = processes
        .iter()
        .find(|process| process.pid() == std::process::id())
        .expect("the current process must be listed");
    assert!(current.matches_name(&expected_name), "{current:?}");
    assert_eq!(
        current
            .exe_path()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned()),
        Some(expected_name.clone())
    );

    let opened = Process::open_by_name(&expected_name).expect("open current process by name");
    assert_eq!(opened.pid(), std::process::id());
    assert!(opened.is_writable());
    assert_eq!(opened.access(), ProcessAccess::ReadWrite);
    assert_eq!(
        opened.name().expect("process name").as_deref(),
        Some(expected_name.as_str())
    );
}

#[test]
fn process_list_reports_the_fixture() {
    let fixture = Fixture::spawn();
    let expected_name = fixture_name();
    let processes = Process::list().expect("process list");
    let fixture_info = processes
        .iter()
        .find(|process| process.pid() == fixture.process.pid())
        .expect("fixture must be listed");
    assert!(fixture_info.matches_name(&expected_name));
    assert_eq!(
        fixture_info
            .exe_path()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned()),
        Some(expected_name)
    );

    let matches = Process::find_by_name(fixture_info.name()).expect("find by name");
    assert!(
        matches
            .iter()
            .any(|process| process.pid() == fixture.process.pid())
    );
}

#[test]
fn unknown_process_name_is_reported() {
    let error =
        Process::open_by_name("memdiver-definitely-not-running-7f3c").expect_err("must fail");
    assert!(
        matches!(error, Error::ProcessNameNotFound { .. }),
        "unexpected {error:?}"
    );
}

#[test]
fn duplicate_process_names_are_reported_as_ambiguous() {
    let first = Fixture::spawn();
    let second = Fixture::spawn();
    let name = fixture_name();
    let error = Process::open_by_name(&name).expect_err("duplicate fixtures must be ambiguous");
    match error {
        Error::AmbiguousProcessName {
            name: reported,
            candidates,
        } => {
            assert_eq!(reported, name);
            assert!(
                candidates
                    .iter()
                    .any(|process| process.pid() == first.process.pid())
            );
            assert!(
                candidates
                    .iter()
                    .any(|process| process.pid() == second.process.pid())
            );
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn read_only_handles_can_read_but_not_write_or_protect() {
    let fixture = Fixture::spawn();
    let readonly = Process::open_readonly(fixture.process.pid()).expect("read-only open");
    assert!(!readonly.is_writable());
    assert_eq!(readonly.access(), ProcessAccess::ReadOnly);

    let bytes = readonly
        .read_bytes(fixture.address, 32)
        .expect("read-only read");
    assert_eq!(bytes, common::pattern(32));

    let error = readonly
        .write(fixture.address, b"nope")
        .expect_err("read-only write must fail");
    assert!(
        matches!(error, Error::ReadOnly { .. }),
        "unexpected {error:?}"
    );

    let error = readonly
        .write_value(fixture.address, 1u32)
        .expect_err("read-only typed write must fail");
    assert!(
        matches!(error, Error::ReadOnly { .. }),
        "unexpected {error:?}"
    );

    let error = readonly
        .protect(fixture.address, 16, Protection::READ)
        .expect_err("read-only protect must fail");
    assert!(
        matches!(error, Error::ReadOnly { .. }),
        "unexpected {error:?}"
    );

    let empty = [];
    readonly
        .write(fixture.address, &empty)
        .expect("zero-length write is a no-op");
}

#[test]
fn read_only_open_still_exposes_identity() {
    let fixture = Fixture::spawn();
    let readonly = Process::open_readonly(fixture.process.pid()).expect("read-only open");
    assert_eq!(readonly.pid(), fixture.process.pid());
    assert_eq!(
        readonly
            .exe_path()
            .expect("executable path")
            .and_then(|path| path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())),
        Some(fixture_name())
    );
}

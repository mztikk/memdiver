//! End-to-end tests for waiting and privilege helpers.
#![allow(missing_docs, unreachable_pub)]

mod common;

use std::thread;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use common::Fixture;
use memdiver::Process;
#[cfg(target_os = "linux")]
use memdiver::{Error, Pattern, ScanOptions};

#[test]
fn wait_reports_timeout_then_exit() {
    let mut fixture = Fixture::spawn();
    assert!(
        !fixture
            .process
            .wait_for_exit(Some(Duration::ZERO))
            .expect("immediate poll"),
        "a live process must not report exit for a zero timeout"
    );
    assert!(
        !fixture
            .process
            .wait_for_exit(Some(Duration::from_millis(50)))
            .expect("timed wait"),
        "a live process must not report exit"
    );
    assert!(fixture.process.is_alive());

    let pid = fixture.process.pid();
    // Open the handle before spawning the waiter so the test does not race the
    // fixture's kill against a late `Process::open`.
    let second_handle = Process::open(pid).expect("second handle");
    let waiter = thread::spawn(move || second_handle.wait_for_exit(Some(Duration::from_secs(5))));
    thread::sleep(Duration::from_millis(50));
    fixture.kill();

    assert!(
        waiter.join().expect("wait thread").expect("wait result"),
        "waiter must observe the exit"
    );
    assert!(
        fixture
            .process
            .wait_for_exit(None)
            .expect("indefinite wait on a dead process"),
        "an already-exited process must return immediately"
    );
    assert!(
        fixture
            .process
            .wait_for_exit(Some(Duration::ZERO))
            .expect("zero timeout after exit"),
        "a second wait on the same handle must still observe exit"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn debug_privilege_is_unsupported_on_linux() {
    let error = memdiver::enable_debug_privilege().expect_err("Linux has no debug privilege");
    assert!(
        matches!(error, memdiver::Error::Unsupported { .. }),
        "unexpected {error:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn exec_invalidates_the_pinned_memory_descriptor() {
    let mut fixture = Fixture::spawn();
    let pid = fixture.process.pid();
    assert!(fixture.process.is_alive());

    fixture.exec();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut buffer = [0u8; 8];
        match fixture.process.read(fixture.address, &mut buffer) {
            Err(Error::AddressSpaceReplaced {
                pid: reported_pid, ..
            }) => {
                assert_eq!(reported_pid, pid);
                break;
            }
            Ok(()) => {}
            Err(other) => panic!("unexpected {other:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "exec did not invalidate the pinned descriptor"
        );
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        fixture.process.is_alive(),
        "the process is still alive after exec"
    );
    let error = fixture
        .process
        .write(fixture.address, b"x")
        .expect_err("a write through a stale descriptor must not succeed");
    assert!(
        matches!(error, Error::AddressSpaceReplaced { .. }),
        "unexpected {error:?}"
    );

    let pattern = Pattern::parse("AA").expect("pattern");
    let error = fixture
        .process
        .find_patterns(&pattern, &ScanOptions::default())
        .expect_err("a scan through a stale descriptor must not silently succeed");
    assert!(
        matches!(error, Error::AddressSpaceReplaced { .. }),
        "unexpected {error:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn device_backed_module_files_are_rejected_before_reading() {
    let mut fixture = Fixture::spawn();
    let address = fixture.zero_target();
    let module = fixture
        .process
        .module_at(address)
        .expect("module lookup")
        .expect("the /dev/zero mapping must be reported as a module");
    assert_eq!(module.name(), "zero");
    assert_eq!(module.path(), std::path::Path::new("/dev/zero"));

    let error = fixture
        .process
        .module_exports(module.name())
        .expect_err("a device-backed module must not be read");
    match error {
        memdiver::Error::ModuleFile { source, .. } => {
            assert_eq!(source.kind(), memdiver::OsErrorKind::MalformedData);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[cfg(windows)]
#[test]
fn debug_privilege_helper_is_opt_in() {
    // On an elevated runner the privilege may already be assigned, so Ok is a
    // valid success. Ordinary CI exercises the structured error branch.
    match memdiver::enable_debug_privilege() {
        Ok(()) => {}
        Err(memdiver::Error::Privilege { source }) => {
            assert!(
                source.raw_code().is_some(),
                "privilege error must keep its OS code"
            );
        }
        Err(other) => panic!("unexpected {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn resolves_libc_exports() {
    let fixture = Fixture::spawn();
    let modules = fixture.process.modules().expect("modules");
    let libc = modules
        .iter()
        .find(|module| module.name().contains("libc"))
        .expect("libc module");
    let exports = fixture
        .process
        .module_exports(libc.name())
        .expect("libc exports");
    assert!(!exports.is_empty(), "libc must export dynamic symbols");
    assert!(
        exports
            .windows(2)
            .all(|pair| pair[0].name() <= pair[1].name()),
        "exports must be sorted by name"
    );

    let symbol = exports
        .iter()
        .find(|export| matches!(export.name(), "malloc" | "free"))
        .expect("libc memory allocation export");
    assert!(libc.contains(symbol.address()));
    assert_eq!(
        fixture
            .process
            .module_export(libc.name(), symbol.name())
            .expect("single export"),
        Some(symbol.address())
    );
    let module = fixture
        .process
        .module(libc.name())
        .expect("module lookup")
        .expect("libc module handle");
    assert_eq!(
        fixture
            .process
            .module_export_of(&module, symbol.name())
            .expect("single export from module handle"),
        Some(symbol.address())
    );

    let error = fixture
        .process
        .module_exports("memdiver-not-loaded")
        .expect_err("unknown module");
    assert!(matches!(error, memdiver::Error::ModuleNotFound { .. }));
}

#[cfg(windows)]
#[test]
fn resolves_ntdll_exports() {
    let fixture = Fixture::spawn();
    let modules = fixture.process.modules().expect("modules");
    let ntdll = modules
        .iter()
        .find(|module| module.name().eq_ignore_ascii_case("ntdll.dll"))
        .expect("ntdll module");
    let exports = fixture
        .process
        .module_exports(ntdll.name())
        .expect("ntdll exports");
    assert!(!exports.is_empty(), "ntdll must export symbols");

    let symbol = exports
        .iter()
        .find(|export| {
            matches!(
                export.name(),
                "NtClose" | "RtlAllocateHeap" | "RtlExitUserProcess"
            )
        })
        .expect("well-known ntdll export");
    assert!(ntdll.contains(symbol.address()));
    assert_eq!(
        fixture
            .process
            .module_export(ntdll.name(), symbol.name())
            .expect("single export"),
        Some(symbol.address())
    );
    let module = fixture
        .process
        .module(ntdll.name())
        .expect("module lookup")
        .expect("ntdll module handle");
    assert_eq!(
        fixture
            .process
            .module_export_of(&module, symbol.name())
            .expect("single export from module handle"),
        Some(symbol.address())
    );
}

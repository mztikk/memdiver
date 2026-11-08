//! End-to-end tests for waiting and privilege helpers.
#![allow(missing_docs, unreachable_pub)]

mod common;

use std::thread;
use std::time::Duration;

use common::Fixture;
use memdiver::Process;

#[test]
fn wait_reports_timeout_then_exit() {
    let mut fixture = Fixture::spawn();
    assert!(
        !fixture
            .process
            .wait_for_exit(Some(Duration::from_millis(50)))
            .expect("timed wait"),
        "a live process must not report exit"
    );
    assert!(fixture.process.is_alive());

    let pid = fixture.process.pid();
    let waiter = thread::spawn(move || {
        Process::open(pid)
            .expect("second handle")
            .wait_for_exit(Some(Duration::from_secs(5)))
    });
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

#[cfg(windows)]
#[test]
fn debug_privilege_helper_is_opt_in() {
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
}

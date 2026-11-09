//! End-to-end tests for the memdiver public API.
#![allow(missing_docs, unreachable_pub)]

mod common;

use std::path::Path;

use common::{Fixture, fixture_name, names_equal};
use memdiver::{Address, Error, Protection};

fn path_name_matches(path: &Path, expected: &str) -> bool {
    path.file_name()
        .map(|name| names_equal(&name.to_string_lossy(), expected))
        .unwrap_or(false)
}

#[test]
fn regions_cover_the_fixture_buffer_and_are_sorted() {
    let fixture = Fixture::spawn();
    let regions = fixture.process.regions().expect("regions");

    assert!(!regions.is_empty());
    for pair in regions.windows(2) {
        assert!(
            pair[0].base() <= pair[1].base(),
            "regions are not sorted: {:?} then {:?}",
            pair[0],
            pair[1]
        );
        assert!(
            pair[0].end() <= pair[1].base(),
            "regions overlap: {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }

    let region = fixture
        .process
        .region_at(fixture.address)
        .expect("region query")
        .expect("buffer address must be inside a region");
    assert!(region.contains(fixture.address));
    assert!(region.is_readable(), "region {region:?}");
    assert!(region.is_writable(), "region {region:?}");
    assert!(region.size() > 0);
    assert!(region.base() <= fixture.address);
    assert!(region.end() > fixture.address);

    let found = regions
        .iter()
        .find(|candidate| candidate.contains(fixture.address))
        .expect("regions list and region_at must agree");
    assert_eq!(&region, found);

    assert!(
        fixture
            .process
            .region_at(Address::NULL)
            .expect("query")
            .is_none(),
        "the null address must not be mapped"
    );
}

#[test]
fn modules_include_the_fixture_executable() {
    let fixture = Fixture::spawn();
    let modules = fixture.process.modules().expect("modules");
    assert!(!modules.is_empty());
    for pair in modules.windows(2) {
        assert!(
            pair[0].base() <= pair[1].base(),
            "modules are not sorted: {:?} then {:?}",
            pair[0],
            pair[1]
        );
    }

    let expected = fixture_name();
    let module = modules
        .iter()
        .find(|module| names_equal(module.name(), &expected))
        .unwrap_or_else(|| panic!("module {expected:?} not found in {modules:?}"));
    assert!(module.size() > 0);
    assert!(module.base().get() > 0);
    assert!(module.contains(module.base()));
    assert!(
        !module.mappings().is_empty(),
        "a loaded module must expose its mapping ranges"
    );
    for &(start, end) in module.mappings() {
        assert!(start < end, "empty module mapping {start:#x}..{end:#x}");
        assert!(start >= module.base().get());
        assert!(end <= module.end().get());
        assert!(module.contains(Address::new(start)));
        assert!(!module.contains(Address::new(end)));
    }
    assert!(path_name_matches(module.path(), &expected));
    assert_eq!(
        fixture
            .process
            .module(module.name())
            .expect("module lookup"),
        Some(module.clone())
    );
    assert_eq!(
        fixture
            .process
            .module("definitely-not-loaded.so")
            .expect("lookup"),
        None
    );

    let regions = fixture.process.regions().expect("regions");
    assert!(
        regions.iter().any(|region| {
            region.is_executable()
                && region
                    .path()
                    .is_some_and(|path| path_name_matches(path, &expected))
        }),
        "no executable region references module {expected:?}: {regions:?}"
    );
}

#[test]
fn snapshot_maps_match_the_vectors() {
    let fixture = Fixture::spawn();
    let regions = fixture.process.regions().expect("regions");
    let region_map = fixture.process.region_map().expect("region map");
    assert_eq!(region_map.len(), regions.len());
    assert_eq!(region_map.is_empty(), regions.is_empty());
    assert_eq!(region_map.regions(), regions.as_slice());
    for region in &regions {
        assert_eq!(
            region_map.find(region.base()).map(|found| found.base()),
            Some(region.base())
        );
    }
    assert!(region_map.find(Address::NULL).is_none());

    let modules = fixture.process.modules().expect("modules");
    let module_map = fixture.process.module_map().expect("module map");
    assert_eq!(module_map.len(), modules.len());
    assert_eq!(module_map.is_empty(), modules.is_empty());
    assert_eq!(module_map.modules(), modules.as_slice());
    for module in &modules {
        assert_eq!(module_map.find(module.base()), Some(module));
    }
}

#[test]
fn empty_protection_ranges_are_rejected() {
    let fixture = Fixture::spawn();
    let error = fixture
        .process
        .protect(fixture.address, 0, Protection::READ)
        .expect_err("empty range must fail");
    assert!(
        matches!(error, Error::InvalidLength { .. }),
        "unexpected {error:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn changing_protection_is_unsupported_on_linux() {
    let fixture = Fixture::spawn();
    let error = fixture
        .process
        .protect(fixture.address, 16, Protection::READ)
        .expect_err("Linux cannot change another process's protection");
    assert!(
        matches!(error, Error::Unsupported { .. }),
        "unexpected {error:?}"
    );
    assert!(error.to_string().contains("not supported"));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_special_mappings_are_private_and_paths_are_absolute() {
    let fixture = Fixture::spawn();
    let regions = fixture.process.regions().expect("regions");

    for region in &regions {
        if let Some(path) = region.path() {
            assert!(
                path.is_absolute(),
                "Linux mapping path must be absolute, got {path:?}"
            );
            assert!(
                !path.to_string_lossy().starts_with('['),
                "special mapping leaked into the path: {path:?}"
            );
        } else {
            assert_eq!(region.kind(), memdiver::RegionKind::Private);
        }
    }
    assert!(
        regions.iter().any(|region| region.path().is_none()),
        "the fixture must have at least one anonymous mapping"
    );

    let modules = fixture.process.modules().expect("modules");
    for module in &modules {
        assert!(
            !module.name().starts_with('[') && !module.name().contains("vdso"),
            "special mapping was reported as a module: {module:?}"
        );
        assert!(module.path().is_absolute());
    }
}

#[cfg(windows)]
#[test]
fn protection_can_be_changed_and_restored_on_windows() {
    let mut fixture = Fixture::spawn();
    let target = fixture.multi_page_target();
    let second = target
        .address
        .checked_add(target.page_size as u64)
        .expect("second page");
    let before = fixture
        .process
        .region_at(second)
        .expect("region query")
        .expect("second page must be mapped");
    assert!(before.is_readable(), "{before:?}");
    assert!(!before.is_writable(), "{before:?}");
    let original = fixture
        .process
        .read_bytes(target.address, target.len)
        .expect("read the multi-page target");

    for invalid in [Protection::WRITE, Protection::WRITE | Protection::EXECUTE] {
        let error = fixture
            .process
            .protect(second, target.page_size, invalid)
            .expect_err("Windows cannot represent this protection");
        assert!(
            matches!(error, Error::InvalidProtection { .. }),
            "unexpected {error:?}"
        );
    }

    let previous = fixture
        .process
        .protect(
            second,
            target.page_size,
            Protection::READ | Protection::WRITE,
        )
        .expect("make the second page writable");
    assert_eq!(previous, Protection::READ);
    let changed = fixture
        .process
        .region_at(second)
        .expect("region query after protect")
        .expect("second page still mapped");
    assert!(changed.is_readable());
    assert!(changed.is_writable());

    let restored = fixture
        .process
        .protect(second, target.page_size, previous)
        .expect("restore the second page");
    assert_eq!(restored, Protection::READ);
    let after = fixture
        .process
        .region_at(second)
        .expect("region query after restore")
        .expect("second page still mapped");
    assert_eq!(
        after.protection(),
        before.protection(),
        "the original protection must be restored"
    );
    assert_eq!(
        fixture
            .process
            .read_bytes(target.address, target.len)
            .expect("read the multi-page target after restore"),
        original,
        "changing and restoring protection must not alter the bytes"
    );
}

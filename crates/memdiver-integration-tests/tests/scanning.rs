//! End-to-end tests for pattern scanning and module attribution.
#![allow(missing_docs, unreachable_pub)]

mod common;

use common::{Fixture, MODULE_SIGNATURE, fixture_name, module_signature_text};
use memdiver::{Address, Error, Pattern, ScanOptions};

fn pattern_for(bytes: &[u8]) -> Pattern {
    let text = bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ");
    Pattern::parse(&text).expect("valid pattern")
}

#[test]
fn find_pattern_enumerates_all_modules() {
    let fixture = Fixture::spawn();
    let pattern = Pattern::parse(&module_signature_text()).expect("signature pattern");

    let hit = fixture
        .process
        .find_pattern(&pattern)
        .expect("scan all modules")
        .expect("fixture signature must be found in a module");
    assert_eq!(
        fixture
            .process
            .read_bytes(hit, MODULE_SIGNATURE.len())
            .expect("read hit"),
        MODULE_SIGNATURE
    );

    let module = fixture
        .process
        .module_at(hit)
        .expect("module lookup")
        .expect("signature hit must be inside a module");
    assert!(module.contains(hit));

    let in_module = fixture
        .process
        .find_pattern_in_module(&fixture_name(), &pattern)
        .expect("scan module")
        .expect("fixture signature must be in its module");
    assert_eq!(
        fixture
            .process
            .read_bytes(in_module, MODULE_SIGNATURE.len())
            .expect("read module hit"),
        MODULE_SIGNATURE
    );

    let module = fixture
        .process
        .module(&fixture_name())
        .expect("module lookup")
        .expect("fixture module");
    assert_eq!(
        fixture
            .process
            .find_pattern_in_module_of(&module, &pattern)
            .expect("scan module snapshot"),
        Some(in_module),
        "the named and snapshot module scans must agree"
    );
    assert!(
        fixture
            .process
            .find_patterns_in_module_of(&module, &pattern, &ScanOptions::default())
            .expect("scan module snapshot for all hits")
            .contains(&in_module)
    );

    let error = fixture
        .process
        .find_pattern_in_module("memdiver-not-loaded", &pattern)
        .expect_err("unknown module must fail");
    assert!(
        matches!(error, Error::ModuleNotFound { .. }),
        "unexpected {error:?}"
    );
}

#[test]
fn region_scans_find_heap_patterns_that_module_scans_do_not() {
    let fixture = Fixture::spawn();
    let bytes = [
        0x13u8, 0x37, 0xA5, 0x5A, 0xC9, 0x2E, 0x74, 0xE1, 0x6B, 0x08, 0xFD, 0x42, 0x9C, 0x55, 0xB8,
        0x24,
    ];
    let address = fixture.address.checked_add(0x400).expect("address");
    fixture
        .process
        .write(address, &bytes)
        .expect("write pattern");

    let pattern = pattern_for(&bytes);
    let hits = fixture
        .process
        .find_patterns(&pattern, &ScanOptions::default())
        .expect("scan all regions");
    assert!(hits.contains(&address), "heap hit missing: {hits:?}");

    let module_hit = fixture
        .process
        .find_pattern(&pattern)
        .expect("scan modules");
    assert_ne!(
        module_hit,
        Some(address),
        "module scan must not include the heap"
    );
    assert!(
        fixture
            .process
            .module_at(address)
            .expect("module lookup")
            .is_none(),
        "heap address must not belong to a module"
    );
}

#[test]
fn finds_pattern_across_adjacent_readable_mappings() {
    let mut fixture = Fixture::spawn();
    let (address, page_size) = fixture.adjacent_target();
    let start = address
        .checked_add((page_size - 8) as u64)
        .expect("boundary start");
    let second = address.checked_add(page_size as u64).expect("second page");
    let first_region = fixture
        .process
        .region_at(address)
        .expect("first region")
        .expect("first page mapped");
    let second_region = fixture
        .process
        .region_at(second)
        .expect("second region")
        .expect("second page mapped");
    assert!(first_region.is_readable());
    assert!(second_region.is_readable());
    assert_ne!(
        first_region.protection(),
        second_region.protection(),
        "the fixture must split the two pages into different protections"
    );

    let boundary_bytes = fixture
        .process
        .read_bytes(start, 16)
        .expect("read across the adjacent mapping boundary");
    let pattern = pattern_for(&boundary_bytes);
    let hits = fixture
        .process
        .find_patterns(&pattern, &ScanOptions::new().with_max_results(0))
        .expect("scan all readable memory");
    assert!(
        hits.contains(&start),
        "the pattern spanning the mapping boundary must be found: {hits:?}"
    );
}

#[test]
fn wildcard_and_nibble_masks_match() {
    let fixture = Fixture::spawn();
    let bytes = [0xA1u8, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
    let address = fixture.address.checked_add(0x500).expect("address");
    fixture
        .process
        .write(address, &bytes)
        .expect("write pattern");

    let pattern = Pattern::parse("A1 B2 ?? D4 ?5 F6 07 1?").expect("wildcard pattern");
    let hits = fixture
        .process
        .find_patterns(&pattern, &ScanOptions::default())
        .expect("scan");
    assert!(hits.contains(&address), "wildcard hit missing: {hits:?}");
}

#[test]
fn alignment_and_result_limit_are_applied() {
    let fixture = Fixture::spawn();
    let bytes = [
        0x77u8, 0x21, 0x4C, 0xE9, 0x03, 0xBA, 0x68, 0xDF, 0x12, 0x9E, 0x35, 0xC0,
    ];
    let base = fixture.address.get();
    let aligned = (base + 0x600 + 15) & !15;
    let unaligned = aligned + 17;
    assert!(unaligned + bytes.len() as u64 <= base + fixture.len as u64);

    fixture
        .process
        .write(Address::new(aligned), &bytes)
        .expect("write aligned");
    fixture
        .process
        .write(Address::new(unaligned), &bytes)
        .expect("write unaligned");

    let pattern = pattern_for(&bytes);
    let aligned_hits = fixture
        .process
        .find_patterns(
            &pattern,
            &ScanOptions::new().with_alignment(16).with_max_results(64),
        )
        .expect("aligned scan");
    assert!(aligned_hits.contains(&Address::new(aligned)));
    assert!(!aligned_hits.contains(&Address::new(unaligned)));

    let limited = fixture
        .process
        .find_patterns(&pattern, &ScanOptions::new().with_max_results(2))
        .expect("limited scan");
    assert_eq!(limited.len(), 2);
}

#[test]
fn result_limit_is_enforced() {
    let fixture = Fixture::spawn();
    let bytes = [
        0x5A, 0xC3, 0x19, 0xE7, 0x42, 0x88, 0x2D, 0xF1, 0x66, 0x0B, 0x94, 0x7C,
    ];
    let pattern = pattern_for(&bytes);
    let base = fixture.address.get();
    for offset in [0x100u64, 0x300, 0x500] {
        fixture
            .process
            .write(Address::new(base + offset), &bytes)
            .expect("write pattern occurrence");
    }

    let limited = fixture
        .process
        .find_patterns(&pattern, &ScanOptions::new().with_max_results(2))
        .expect("limited scan");
    assert_eq!(
        limited.len(),
        2,
        "the scan must stop at max_results even with more matches: {limited:?}"
    );
    assert!(limited[0] < limited[1]);

    let unlimited = fixture
        .process
        .find_patterns(&pattern, &ScanOptions::new().with_max_results(0))
        .expect("unlimited scan");
    assert!(
        unlimited.len() >= 3,
        "all three occurrences must be found: {unlimited:?}"
    );
}

#[test]
fn module_at_reports_module_bounds() {
    let fixture = Fixture::spawn();
    let module = fixture
        .process
        .module(&fixture_name())
        .expect("module lookup")
        .expect("fixture module");
    assert_eq!(
        fixture
            .process
            .module_at(module.base())
            .expect("module at base"),
        Some(module.clone())
    );
    let last = module.end().checked_sub(1).expect("non-empty module");
    assert_eq!(
        fixture.process.module_at(last).expect("module at end"),
        Some(module)
    );
}

#[test]
fn finds_typed_values_in_memory_and_modules() {
    let fixture = Fixture::spawn();
    let value = 0xDEAD_BEEF_CAFE_F00D_u64;
    let address = Address::new((fixture.address.get() + 0x600 + 7) & !7);
    fixture
        .process
        .write_value(address, value)
        .expect("write value");
    assert!(address.get() + 8 <= fixture.address.get() + fixture.len as u64);

    let options = ScanOptions::new().with_alignment(8);
    let all = fixture
        .process
        .find_values(value, &options)
        .expect("value scan");
    assert!(all.contains(&address), "value hit missing: {all:?}");

    let in_modules = fixture
        .process
        .find_values_in_modules(value, &options)
        .expect("module value scan");
    assert!(!in_modules.contains(&address));

    let in_module = fixture
        .process
        .find_values_in_module(&fixture_name(), value, &options)
        .expect("single module value scan");
    assert!(!in_module.contains(&address));

    let module = fixture
        .process
        .module(&fixture_name())
        .expect("module lookup")
        .expect("fixture module");
    let in_module_of = fixture
        .process
        .find_values_in_module_of(&module, value, &options)
        .expect("single module snapshot value scan");
    assert_eq!(in_module_of, in_module);
}

#[test]
fn zero_sized_value_scan_is_rejected() {
    let fixture = Fixture::spawn();
    let error = fixture
        .process
        .find_values([0u8; 0], &ScanOptions::default())
        .expect_err("zero-sized value must fail");
    assert!(
        matches!(error, Error::InvalidPattern { .. }),
        "unexpected {error:?}"
    );
}

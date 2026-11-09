//! Pattern scanning across process memory.

use std::mem::size_of;

use memchr::memchr;
use memdiver_sys::ErrorKind as OsErrorKind;

use crate::{Address, Error, Module, Pattern, Process, Result, ScanOptions};

/// Number of new bytes covered by each scan chunk.
const SCAN_CHUNK: usize = 1024 * 1024;

impl Process {
    /// Finds the first occurrence of `pattern` in any loaded module.
    ///
    /// Modules are searched in ascending load-address order, so the result is
    /// the first hit in module order. Only readable, non-guard regions inside
    /// the module's own mappings are scanned; adjacent readable regions are coalesced so a
    /// pattern crossing a mapping boundary is still found. Unreadable regions
    /// and ordinary failed chunk reads are skipped, while an exited or replaced
    /// process aborts the scan.
    ///
    /// # Errors
    ///
    /// Returns an error when the module or region list cannot be enumerated.
    pub fn find_pattern(&self, pattern: &Pattern) -> Result<Option<Address>> {
        let modules = self.modules()?;
        let regions = self.scan_regions()?;
        let options = ScanOptions::default();
        let mut hits = Vec::new();
        for module in &modules {
            hits.clear();
            self.scan_module(module, &regions, pattern, &options, 1, &mut hits)?;
            if let Some(hit) = hits.first() {
                return Ok(Some(*hit));
            }
        }
        Ok(None)
    }

    /// Finds the first occurrence of `pattern` in one named module.
    ///
    /// The module name is matched exactly. Unreadable regions and failed chunk
    /// reads are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ModuleNotFound`] when the module is not loaded, or an
    /// error when the region list cannot be enumerated.
    pub fn find_pattern_in_module(
        &self,
        module: &str,
        pattern: &Pattern,
    ) -> Result<Option<Address>> {
        let module = self.module(module)?.ok_or_else(|| Error::ModuleNotFound {
            pid: self.pid,
            name: module.to_owned(),
        })?;
        let regions = self.scan_regions()?;
        let mut hits = Vec::new();
        self.scan_module(
            &module,
            &regions,
            pattern,
            &ScanOptions::default(),
            1,
            &mut hits,
        )?;
        Ok(hits.first().copied())
    }

    /// Finds all occurrences of `pattern` in loaded modules.
    ///
    /// Modules are searched in ascending load-address order. Unreadable regions
    /// and failed chunk reads are skipped. Results are returned in ascending
    /// address order and bounded by [`ScanOptions::max_results`].
    ///
    /// # Errors
    ///
    /// Returns an error when the module or region list cannot be enumerated, or
    /// when an output buffer cannot be allocated.
    pub fn find_patterns_in_modules(
        &self,
        pattern: &Pattern,
        options: &ScanOptions,
    ) -> Result<Vec<Address>> {
        let modules = self.modules()?;
        let regions = self.scan_regions()?;
        let mut hits = Vec::new();
        let limit = result_limit(options);
        for module in &modules {
            self.scan_module(module, &regions, pattern, options, limit, &mut hits)?;
            if hits.len() >= limit {
                break;
            }
        }
        Ok(hits)
    }

    /// Finds all occurrences of `pattern` in readable process memory.
    ///
    /// This scans every committed, readable, non-guard region, including heap,
    /// stacks and modules. Adjacent readable regions are coalesced so patterns
    /// crossing a mapping boundary are found. Results are returned in ascending
    /// address order and bounded by [`ScanOptions::max_results`].
    ///
    /// # Errors
    ///
    /// Returns an error when the region list cannot be enumerated or an output
    /// buffer cannot be allocated.
    pub fn find_patterns(&self, pattern: &Pattern, options: &ScanOptions) -> Result<Vec<Address>> {
        let regions = self.scan_regions()?;
        let mut hits = Vec::new();
        let limit = result_limit(options);
        for range in scan_ranges(&regions, None) {
            scan_range_with(
                self.pid,
                range.base,
                range.size,
                pattern,
                options,
                limit,
                &mut hits,
                |address, buffer| self.read(address, buffer),
            )?;
            if hits.len() >= limit {
                break;
            }
        }
        Ok(hits)
    }

    /// Finds all occurrences of `pattern` in one named module.
    ///
    /// The module name is matched exactly. Results are returned in ascending
    /// address order and bounded by [`ScanOptions::max_results`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ModuleNotFound`] when the module is not loaded, an
    /// error when the region list cannot be enumerated, or an allocation error.
    pub fn find_patterns_in_module(
        &self,
        module: &str,
        pattern: &Pattern,
        options: &ScanOptions,
    ) -> Result<Vec<Address>> {
        let module = self.module(module)?.ok_or_else(|| Error::ModuleNotFound {
            pid: self.pid,
            name: module.to_owned(),
        })?;
        let regions = self.scan_regions()?;
        let mut hits = Vec::new();
        self.scan_module(
            &module,
            &regions,
            pattern,
            options,
            result_limit(options),
            &mut hits,
        )?;
        Ok(hits)
    }

    fn scan_module(
        &self,
        module: &Module,
        regions: &[crate::Region],
        pattern: &Pattern,
        options: &ScanOptions,
        limit: usize,
        hits: &mut Vec<Address>,
    ) -> Result<()> {
        for range in scan_ranges(regions, Some(module)) {
            scan_range_with(
                self.pid,
                range.base,
                range.size,
                pattern,
                options,
                limit,
                hits,
                |address, buffer| self.read(address, buffer),
            )?;
            if hits.len() >= limit {
                break;
            }
        }
        Ok(())
    }
}

fn scan_region(region: &crate::Region) -> bool {
    region.is_readable() && !region.protection().is_guarded()
}

/// A contiguous range to scan, after merging adjacent readable regions and
/// clipping to a module when one is supplied.
struct ScanRange {
    base: Address,
    size: u64,
}

/// Builds the ranges a scan must read.
///
/// Adjacent readable regions are merged so a pattern that crosses a mapping
/// boundary is still found; the underlying read works across adjacent mappings
/// and the range stays inside readable memory. Module scans clip every region
/// to the module span first.
fn scan_ranges(regions: &[crate::Region], module: Option<&Module>) -> Vec<ScanRange> {
    let mut ranges: Vec<ScanRange> = Vec::new();
    for region in regions {
        if !scan_region(region) {
            continue;
        }
        match module {
            Some(module) => {
                // Only the module's own mappings are scanned; a readable
                // mapping in an unmapped gap of the module's span does not
                // belong to the module.
                for &(mapping_start, mapping_end) in module.mappings() {
                    let start = region.base().get().max(mapping_start);
                    let end = region.end().get().min(mapping_end);
                    push_scan_range(&mut ranges, start, end);
                }
            }
            None => push_scan_range(&mut ranges, region.base().get(), region.end().get()),
        }
    }
    ranges
}

/// Appends a half-open range, merging it with the previous one when adjacent.
fn push_scan_range(ranges: &mut Vec<ScanRange>, start: u64, end: u64) {
    if end <= start {
        return;
    }
    if let Some(last) = ranges.last_mut() {
        let last_end = last.base.get().saturating_add(last.size);
        if last_end == start {
            last.size = last.size.saturating_add(end - start);
            return;
        }
    }
    ranges.push(ScanRange {
        base: Address::new(start),
        size: end - start,
    });
}

/// Returns `true` when a failed chunk read means the whole scan is invalid
/// rather than merely unreadable memory.
///
/// Address-space replacement and process exit are terminal; an unmapped chunk,
/// permission failure or short transfer is normal best-effort noise for a scan.
fn is_fatal_scan_error(error: &Error) -> bool {
    match error {
        Error::AddressSpaceReplaced { .. } => true,
        Error::Read { source, .. } => matches!(source.kind(), OsErrorKind::ProcessExited),
        _ => false,
    }
}

fn result_limit(options: &ScanOptions) -> usize {
    if options.max_results() == 0 {
        usize::MAX
    } else {
        options.max_results()
    }
}

// The parameters are the range, its process context, the pattern/options and the
// output buffer; a context struct would obscure the hot call sites for little
// benefit.
#[allow(clippy::too_many_arguments)]
fn scan_range_with<F>(
    pid: u32,
    base: Address,
    size: u64,
    pattern: &Pattern,
    options: &ScanOptions,
    limit: usize,
    hits: &mut Vec<Address>,
    mut read: F,
) -> Result<()>
where
    F: FnMut(Address, &mut [u8]) -> Result<()>,
{
    let pattern_len = pattern.len();
    if pattern_len == 0 || size < pattern_len as u64 || hits.len() >= limit {
        return Ok(());
    }

    let step = SCAN_CHUNK.max(pattern_len);
    let step_u64 = step as u64;
    let overlap = pattern_len as u64 - 1;
    let max_buffer_len = step_u64.saturating_add(overlap).min(size);
    let max_buffer_len = usize::try_from(max_buffer_len).map_err(|_| Error::InvalidLength {
        pid,
        operation: "pattern scan",
        address: base,
        len: usize::MAX,
    })?;

    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(max_buffer_len)
        .map_err(|source| Error::Allocation {
            len: max_buffer_len,
            source,
        })?;

    let mut offset = 0u64;
    while offset < size && hits.len() < limit {
        let Some(address) = base.checked_add(offset) else {
            break;
        };
        let want = step_u64.saturating_add(overlap).min(size - offset);
        let want = usize::try_from(want).map_err(|_| Error::InvalidLength {
            pid,
            operation: "pattern scan",
            address,
            len: usize::MAX,
        })?;
        if want < pattern_len {
            break;
        }
        buffer.clear();
        buffer.resize(want, 0);
        match read(address, &mut buffer) {
            Ok(()) => scan_buffer(&buffer, address, pattern, options, limit, hits)?,
            Err(error) if is_fatal_scan_error(&error) => return Err(error),
            Err(_) => {}
        }
        offset = offset.saturating_add(step_u64);
    }
    Ok(())
}

fn scan_buffer(
    buffer: &[u8],
    base: Address,
    pattern: &Pattern,
    options: &ScanOptions,
    limit: usize,
    hits: &mut Vec<Address>,
) -> Result<()> {
    let pattern_len = pattern.len();
    if pattern_len == 0 || pattern_len > buffer.len() {
        return Ok(());
    }
    let last_start = buffer.len() - pattern_len;
    let alignment = options.alignment().max(1) as u64;
    let base_value = base.get();
    let mut search = 0usize;

    while search <= last_start && hits.len() < limit {
        let candidate = if let Some((anchor_index, needle)) = pattern.anchor() {
            let Some(anchor_start) = search.checked_add(anchor_index) else {
                break;
            };
            let anchor_end = last_start + anchor_index;
            if anchor_start > anchor_end {
                break;
            }
            let Some(relative) = memchr(needle, &buffer[anchor_start..=anchor_end]) else {
                break;
            };
            anchor_start + relative - anchor_index
        } else {
            search
        };

        let Some(absolute) = base_value.checked_add(candidate as u64) else {
            break;
        };
        if (alignment == 1 || absolute % alignment == 0)
            && pattern.matches_at(&buffer[candidate..candidate + pattern_len])
        {
            hits.try_reserve(1).map_err(|source| Error::Allocation {
                len: size_of::<Address>().saturating_mul(hits.len().saturating_add(1)),
                source,
            })?;
            hits.push(Address::new(absolute));
            if hits.len() >= limit {
                break;
            }
        }
        search = candidate + 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Protection, RegionKind};

    const BASE: u64 = 0x1000;

    fn run_scan_at(
        base: u64,
        data: &[u8],
        pattern: &Pattern,
        options: &ScanOptions,
        limit: usize,
    ) -> Vec<Address> {
        let mut hits = Vec::new();
        scan_range_with(
            1,
            Address::new(base),
            data.len() as u64,
            pattern,
            options,
            limit,
            &mut hits,
            |address, buffer| {
                let offset = usize::try_from(address.get() - base).expect("offset");
                buffer.copy_from_slice(&data[offset..offset + buffer.len()]);
                Ok(())
            },
        )
        .expect("scan");
        hits
    }

    fn run_scan(
        data: &[u8],
        pattern: &Pattern,
        options: &ScanOptions,
        limit: usize,
    ) -> Vec<Address> {
        run_scan_at(BASE, data, pattern, options, limit)
    }

    fn test_region(base: u64, size: u64, protection: Protection) -> crate::Region {
        crate::Region::from_raw(memdiver_sys::RawRegion {
            base,
            size,
            protection,
            kind: RegionKind::Private,
            path: None,
        })
    }

    #[test]
    fn scan_ranges_merge_adjacent_readable_regions() {
        let regions = vec![
            test_region(0x1000, 0x1000, Protection::READ),
            test_region(0x2000, 0x1000, Protection::READ | Protection::WRITE),
            // A gap breaks the run.
            test_region(0x4000, 0x1000, Protection::READ),
            // An unreadable region is skipped and also breaks the run.
            test_region(0x5000, 0x1000, Protection::empty()),
            test_region(0x6000, 0x1000, Protection::READ),
        ];
        let ranges = scan_ranges(&regions, None);
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].base, Address::new(0x1000));
        assert_eq!(ranges[0].size, 0x2000);
        assert_eq!(ranges[1].base, Address::new(0x4000));
        assert_eq!(ranges[1].size, 0x1000);
        assert_eq!(ranges[2].base, Address::new(0x6000));
        assert_eq!(ranges[2].size, 0x1000);
    }

    #[test]
    fn scan_ranges_clip_to_a_module_before_merging() {
        let module = Module::from_raw(memdiver_sys::RawModule {
            name: "test".to_owned(),
            path: std::path::PathBuf::from("/test"),
            base: 0x1800,
            size: 0x1000,
            mappings: vec![(0x1800, 0x2800)],
        });
        let regions = vec![
            test_region(0x1000, 0x1000, Protection::READ),
            test_region(0x2000, 0x1000, Protection::READ),
        ];
        let ranges = scan_ranges(&regions, Some(&module));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].base, Address::new(0x1800));
        assert_eq!(ranges[0].size, 0x1000);
    }

    #[test]
    fn scan_ranges_do_not_scan_span_gaps() {
        let module = Module::from_raw(memdiver_sys::RawModule {
            name: "gapped".to_owned(),
            path: std::path::PathBuf::from("/gapped"),
            base: 0x1000,
            size: 0x3000,
            mappings: vec![(0x1000, 0x1100), (0x3000, 0x3100)],
        });
        let regions = vec![
            test_region(0x1000, 0x100, Protection::READ),
            test_region(0x2000, 0x100, Protection::READ),
            test_region(0x3000, 0x100, Protection::READ),
        ];
        let ranges = scan_ranges(&regions, Some(&module));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].base, Address::new(0x1000));
        assert_eq!(ranges[0].size, 0x100);
        assert_eq!(ranges[1].base, Address::new(0x3000));
        assert_eq!(ranges[1].size, 0x100);
    }

    #[test]
    fn finds_pattern_across_chunk_boundary() {
        // The first chunk covers [0, SCAN_CHUNK + pattern_len - 1). Placing the
        // match at SCAN_CHUNK + 2 makes it spill past the first chunk, so only
        // the second chunk (which starts at SCAN_CHUNK) can find it. This
        // exercises the step/dedup path rather than the intra-chunk path.
        let mut data = vec![0u8; SCAN_CHUNK * 2 + 64];
        let pattern = Pattern::parse("DE AD BE EF 11 22 33 44").expect("pattern");
        let position = SCAN_CHUNK + 2;
        data[position..position + 8]
            .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44]);
        let hits = run_scan(&data, &pattern, &ScanOptions::default(), 10);
        assert_eq!(hits, vec![Address::new(BASE + position as u64)]);
    }

    #[test]
    fn alignment_uses_the_absolute_address() {
        let mut data = [0u8; 16];
        data[5] = 0xAA;
        data[6] = 0xAA;
        let pattern = Pattern::parse("AA").expect("pattern");
        let options = ScanOptions::new().with_alignment(4);
        let hits = run_scan_at(0x1003, &data, &pattern, &options, 10);
        assert_eq!(
            hits,
            vec![Address::new(0x1008)],
            "0x1008 is 4-aligned; 0x1009 is not"
        );
    }

    #[test]
    fn respects_alignment_and_result_limit() {
        let mut data = vec![0u8; 64];
        for position in [4usize, 9, 12] {
            data[position] = 0xAA;
            data[position + 1] = 0xBB;
        }
        let pattern = Pattern::parse("AA BB").expect("pattern");
        let aligned = run_scan(&data, &pattern, &ScanOptions::new().with_alignment(4), 10);
        assert_eq!(
            aligned,
            vec![Address::new(BASE + 4), Address::new(BASE + 12)]
        );
        let limited = run_scan(&data, &pattern, &ScanOptions::default(), 2);
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn skips_failed_chunk_reads() {
        let mut data = [0u8; 32];
        data[0] = 0xAA;
        data[1] = 0xBB;
        let pattern = Pattern::parse("AA BB").expect("pattern");
        let mut hits = Vec::new();
        scan_range_with(
            1,
            Address::new(BASE),
            data.len() as u64,
            &pattern,
            &ScanOptions::default(),
            10,
            &mut hits,
            |_, _| {
                Err(Error::InvalidLength {
                    pid: 1,
                    operation: "test",
                    address: Address::new(BASE),
                    len: 0,
                })
            },
        )
        .expect("scan");
        assert!(hits.is_empty());
    }

    #[test]
    fn finds_pattern_with_leading_wildcard() {
        let mut data = vec![0u8; 32];
        data[10] = 0xAA;
        data[11] = 0xBB;
        data[12] = 0xCC;
        let pattern = Pattern::parse("?? AA BB CC").expect("pattern");
        let hits = run_scan(&data, &pattern, &ScanOptions::default(), 10);
        assert_eq!(hits, vec![Address::new(BASE + 9)]);
    }

    #[test]
    fn matches_overlapping_occurrences() {
        let data = [0xAA, 0xAA, 0xAA, 0xAA];
        let pattern = Pattern::parse("AA AA").expect("pattern");
        let hits = run_scan(&data, &pattern, &ScanOptions::default(), 10);
        assert_eq!(
            hits,
            vec![
                Address::new(BASE),
                Address::new(BASE + 1),
                Address::new(BASE + 2)
            ]
        );
    }
}

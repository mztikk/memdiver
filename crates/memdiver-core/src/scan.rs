//! Pattern scanning across process memory.

use memchr::memchr;

use crate::{Address, Error, Module, Pattern, Process, Result, ScanOptions};

/// Number of new bytes covered by each scan chunk.
const SCAN_CHUNK: usize = 1024 * 1024;

impl Process {
    /// Finds the first occurrence of `pattern` in any loaded module.
    ///
    /// Modules are searched in ascending load-address order, so the result is
    /// the first hit in module order. Only readable, non-guard regions inside
    /// module bounds are scanned. Unreadable regions and failed chunk reads are
    /// skipped; this makes the scan best-effort over a live process.
    ///
    /// # Errors
    ///
    /// Returns an error when the module or region list cannot be enumerated.
    pub fn find_pattern(&self, pattern: &Pattern) -> Result<Option<Address>> {
        let modules = self.modules()?;
        let regions = self.regions()?;
        let options = ScanOptions::default();
        for module in &modules {
            let mut hits = Vec::new();
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
            name: module.to_owned(),
        })?;
        let regions = self.regions()?;
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
        let regions = self.regions()?;
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
    /// stacks and modules. Results are returned in ascending address order and
    /// bounded by [`ScanOptions::max_results`].
    ///
    /// # Errors
    ///
    /// Returns an error when the region list cannot be enumerated or an output
    /// buffer cannot be allocated.
    pub fn find_patterns(&self, pattern: &Pattern, options: &ScanOptions) -> Result<Vec<Address>> {
        let regions = self.regions()?;
        let mut hits = Vec::new();
        let limit = result_limit(options);
        for region in &regions {
            if !scan_region(region) {
                continue;
            }
            scan_range_with(
                region.base(),
                region.size(),
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
            name: module.to_owned(),
        })?;
        let regions = self.regions()?;
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
        for region in regions {
            if !scan_region(region) {
                continue;
            }
            let start = region.base().get().max(module.base().get());
            let end = region.end().get().min(module.end().get());
            if end <= start {
                continue;
            }
            scan_range_with(
                Address::new(start),
                end - start,
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

fn result_limit(options: &ScanOptions) -> usize {
    if options.max_results() == 0 {
        usize::MAX
    } else {
        options.max_results()
    }
}

fn scan_range_with<F>(
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
        operation: "pattern scan",
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
        let want = step_u64.saturating_add(overlap).min(size - offset);
        let want = usize::try_from(want).map_err(|_| Error::InvalidLength {
            operation: "pattern scan",
            len: usize::MAX,
        })?;
        if want < pattern_len {
            break;
        }
        buffer.clear();
        buffer.resize(want, 0);
        let Some(address) = base.checked_add(offset) else {
            break;
        };
        if read(address, &mut buffer).is_ok() {
            scan_buffer(&buffer, address, pattern, options, limit, hits);
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
) {
    let pattern_len = pattern.len();
    if pattern_len == 0 || pattern_len > buffer.len() {
        return;
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

        let Some(absolute) = base_value.checked_add(u64::try_from(candidate).unwrap_or(u64::MAX))
        else {
            break;
        };
        if (alignment == 1 || absolute % alignment == 0)
            && pattern.matches_at(&buffer[candidate..candidate + pattern_len])
        {
            hits.push(Address::new(absolute));
            if hits.len() >= limit {
                break;
            }
        }
        search = candidate + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000;

    fn run_scan(
        data: &[u8],
        pattern: &Pattern,
        options: &ScanOptions,
        limit: usize,
    ) -> Vec<Address> {
        let mut hits = Vec::new();
        scan_range_with(
            Address::new(BASE),
            data.len() as u64,
            pattern,
            options,
            limit,
            &mut hits,
            |address, buffer| {
                let offset = usize::try_from(address.get() - BASE).expect("offset");
                buffer.copy_from_slice(&data[offset..offset + buffer.len()]);
                Ok(())
            },
        )
        .expect("scan");
        hits
    }

    #[test]
    fn finds_pattern_across_chunk_boundary() {
        let mut data = vec![0u8; SCAN_CHUNK + 64];
        let pattern = Pattern::parse("DE AD BE EF 11 22 33 44").expect("pattern");
        let position = SCAN_CHUNK - 3;
        data[position..position + 8]
            .copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44]);
        let hits = run_scan(&data, &pattern, &ScanOptions::default(), 10);
        assert_eq!(hits, vec![Address::new(BASE + position as u64)]);
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
            Address::new(BASE),
            data.len() as u64,
            &pattern,
            &ScanOptions::default(),
            10,
            &mut hits,
            |_, _| {
                Err(Error::InvalidLength {
                    operation: "test",
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

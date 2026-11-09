//! Committed memory regions.

use std::path::Path;

use memdiver_sys::RawRegion;

use crate::{Address, Protection, RegionKind};

/// A committed memory region in the target process.
///
/// Regions are a snapshot of the target's virtual memory at the time
/// [`crate::Process::regions`](crate::Process::regions) was called. They do not update
/// when the target changes its mappings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    base: Address,
    size: u64,
    protection: Protection,
    kind: RegionKind,
    path: Option<std::path::PathBuf>,
}

impl Region {
    pub(crate) fn from_raw(raw: RawRegion) -> Self {
        Self {
            base: Address::new(raw.base),
            size: raw.size,
            protection: raw.protection,
            kind: raw.kind,
            path: raw.path,
        }
    }

    /// Returns the first address of the region.
    #[must_use]
    pub fn base(&self) -> Address {
        self.base
    }

    /// Returns the size of the region in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the first address after the region.
    ///
    /// The addition saturates at [`u64::MAX`]; operating systems never report a
    /// region that wraps the address space.
    #[must_use]
    pub fn end(&self) -> Address {
        Address::new(self.base.get().saturating_add(self.size))
    }

    /// Returns the access protection of the region.
    #[must_use]
    pub fn protection(&self) -> Protection {
        self.protection
    }

    /// Returns what backs the region.
    #[must_use]
    pub fn kind(&self) -> RegionKind {
        self.kind
    }

    /// Returns the file backing the region, when the platform reports one.
    ///
    /// Linux reports the file for every file-backed mapping and `None` for
    /// anonymous mappings such as the heap and stack. Windows reports a path
    /// only when the region belongs to a loaded module; the path is best-effort
    /// metadata and is `None` for other mapped sections.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Returns `true` when `address` lies inside this region.
    #[must_use]
    pub fn contains(&self, address: Address) -> bool {
        address.get() >= self.base.get() && address.get() - self.base.get() < self.size
    }

    /// Returns `true` when the region is readable.
    #[must_use]
    pub fn is_readable(&self) -> bool {
        self.protection.is_readable()
    }

    /// Returns `true` when the region is writable.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.protection.is_writable()
    }

    /// Returns `true` when the region is executable.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.protection.is_executable()
    }
}

/// A sorted snapshot of a process's committed regions with binary-search
/// lookups.
///
/// Use this when looking up more than one address: [`crate::Process::region_at`]
/// re-enumerates the process for every call, while a `RegionMap` enumerates
/// once. The snapshot is stale as soon as it is created, just like the vector
/// returned by [`crate::Process::regions`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionMap {
    regions: Vec<Region>,
}

impl RegionMap {
    pub(crate) fn new(regions: Vec<Region>) -> Self {
        Self { regions }
    }

    /// Returns all regions, sorted by base address.
    #[must_use]
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// Returns the region containing `address`, if any.
    #[must_use]
    pub fn find(&self, address: Address) -> Option<&Region> {
        find_range(
            &self.regions,
            address,
            |region| region.base().get(),
            Region::contains,
        )
    }

    /// Returns `true` when the snapshot contains no regions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Returns the number of regions in the snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.regions.len()
    }
}

/// Finds the last item in a sorted slice whose base is at or before `address`
/// and that contains the address.
///
/// Both [`RegionMap`] and [`ModuleMap`](crate::ModuleMap) use this so their
/// lookup semantics cannot diverge. Items must be sorted by `base` and their
/// ranges must not overlap.
pub(crate) fn find_range<T>(
    items: &[T],
    address: Address,
    base: impl Fn(&T) -> u64,
    contains: impl Fn(&T, Address) -> bool,
) -> Option<&T> {
    let index = items.partition_point(|item| base(item) <= address.get());
    index
        .checked_sub(1)
        .and_then(|index| items.get(index))
        .filter(|item| contains(item, address))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn region(base: u64, size: u64) -> Region {
        Region::from_raw(RawRegion {
            base,
            size,
            protection: Protection::READ | Protection::WRITE,
            kind: RegionKind::Private,
            path: Some(PathBuf::from("/tmp/example")),
        })
    }

    #[test]
    fn exposes_properties() {
        let region = region(0x1000, 0x200);
        assert_eq!(region.base(), Address::new(0x1000));
        assert_eq!(region.size(), 0x200);
        assert_eq!(region.end(), Address::new(0x1200));
        assert!(region.is_readable());
        assert!(region.is_writable());
        assert!(!region.is_executable());
        assert_eq!(region.path(), Some(Path::new("/tmp/example")));
    }

    #[test]
    fn containment_is_half_open() {
        let region = region(0x1000, 0x200);
        assert!(!region.contains(Address::new(0xfff)));
        assert!(region.contains(Address::new(0x1000)));
        assert!(region.contains(Address::new(0x11ff)));
        assert!(!region.contains(Address::new(0x1200)));
    }

    #[test]
    fn map_finds_regions_by_address() {
        let map = RegionMap::new(vec![region(0x1000, 0x200), region(0x2000, 0x100)]);
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        assert_eq!(
            map.find(Address::new(0x1100)).map(Region::base),
            Some(Address::new(0x1000))
        );
        assert_eq!(
            map.find(Address::new(0x2000)).map(Region::base),
            Some(Address::new(0x2000))
        );
        assert!(map.find(Address::new(0x1200)).is_none());
        assert!(map.find(Address::NULL).is_none());
        assert_eq!(map.regions().len(), 2);
    }

    #[test]
    fn end_saturates_at_address_space_limit() {
        let region = region(u64::MAX - 1, 10);
        assert_eq!(region.end(), Address::new(u64::MAX));
        assert!(region.contains(Address::new(u64::MAX)));
    }
}

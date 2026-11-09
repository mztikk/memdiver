//! Loaded executable modules.

use std::path::{Path, PathBuf};

use memdiver_sys::RawModule;

use crate::{Address, Error, Result};

/// An executable module loaded by the target process.
///
/// On Windows these are the executables and DLLs from the process module list,
/// read through the pinned handle with `EnumProcessModulesEx`. On Linux these
/// are file-backed mappings with at least one executable segment; all segments
/// of the same file are merged into one module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    name: String,
    path: PathBuf,
    base: Address,
    size: u64,
    mappings: Vec<(u64, u64)>,
}

impl Module {
    pub(crate) fn from_raw(raw: RawModule) -> Self {
        Self {
            name: raw.name,
            path: raw.path,
            base: Address::new(raw.base),
            size: raw.size,
            mappings: raw.mappings,
        }
    }

    /// Returns the module name reported by the platform.
    ///
    /// This is normally the file name. Names that are not valid Unicode are
    /// converted lossily on both platforms; use [`Module::path`] when the exact
    /// bytes matter.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the full path recorded by the platform.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the load address of the module.
    #[must_use]
    pub fn base(&self) -> Address {
        self.base
    }

    /// Returns the size of the module's mapping span in bytes.
    ///
    /// The span is the distance from [`Module::base`] to the end of the
    /// module's highest mapping. It can include unmapped gaps; use
    /// [`Module::contains`] or [`Module::mappings`] for exact containment.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the module's own half-open mapping ranges.
    ///
    /// The ranges are sorted, non-overlapping and lie inside
    /// `base()..base() + size()`. Windows reports one contiguous image range;
    /// Linux can report several ranges for a file-backed module.
    #[must_use]
    pub fn mappings(&self) -> &[(u64, u64)] {
        &self.mappings
    }

    /// Returns the first address after the module's mapping.
    ///
    /// The addition saturates at [`u64::MAX`].
    #[must_use]
    pub fn end(&self) -> Address {
        Address::new(self.base.get().saturating_add(self.size))
    }

    /// Returns `true` when `address` lies inside one of the module's mappings.
    ///
    /// Addresses in an unmapped gap inside the module's span are not contained.
    #[must_use]
    pub fn contains(&self, address: Address) -> bool {
        self.mappings
            .iter()
            .any(|&(start, end)| address.get() >= start && address.get() < end)
    }
}

/// A snapshot of a process's loaded modules with binary-search lookups.
///
/// Use this when looking up more than one address: [`crate::Process::module_at`]
/// re-enumerates the process for every call, while a `ModuleMap` enumerates
/// once. The snapshot is stale as soon as it is created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleMap {
    modules: Vec<Module>,
}

impl ModuleMap {
    pub(crate) fn new(modules: Vec<Module>) -> Self {
        Self { modules }
    }

    /// Returns all modules, sorted by load address.
    #[must_use]
    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    /// Returns the module containing `address`, if any.
    #[must_use]
    pub fn find(&self, address: Address) -> Option<&Module> {
        let index = self
            .modules
            .partition_point(|module| module.base() <= address);
        index
            .checked_sub(1)
            .and_then(|index| self.modules.get(index))
            .filter(|module| module.contains(address))
    }

    /// Returns `true` when the snapshot contains no modules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Returns the number of modules in the snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.modules.len()
    }
}

/// Selects the one module matching `name`, or reports ambiguity.
///
/// `None` means no module matched; `Some` contains the unique match. The caller
/// supplies `pid` for error context.
pub(crate) fn unique_module(
    mut candidates: Vec<Module>,
    name: &str,
    pid: u32,
) -> Result<Option<Module>> {
    match candidates.len() {
        0 => Ok(None),
        1 => Ok(candidates.pop()),
        _ => Err(Error::AmbiguousModuleName {
            pid,
            name: name.to_owned(),
            candidates,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module() -> Module {
        Module::from_raw(RawModule {
            name: "example.so".to_owned(),
            path: PathBuf::from("/usr/lib/example.so"),
            base: 0x4000,
            size: 0x1000,
            mappings: vec![(0x4000, 0x5000)],
        })
    }

    #[test]
    fn exposes_properties() {
        let module = module();
        assert_eq!(module.name(), "example.so");
        assert_eq!(module.path(), Path::new("/usr/lib/example.so"));
        assert_eq!(module.base(), Address::new(0x4000));
        assert_eq!(module.size(), 0x1000);
        assert_eq!(module.end(), Address::new(0x5000));
        assert_eq!(module.mappings(), &[(0x4000, 0x5000)]);
    }

    #[test]
    fn map_finds_modules_by_address() {
        let map = ModuleMap::new(vec![module()]);
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
        assert_eq!(
            map.find(Address::new(0x4000)).map(Module::name),
            Some("example.so")
        );
        assert!(map.find(Address::new(0x5000)).is_none());
        assert_eq!(map.modules().len(), 1);
    }

    #[test]
    fn unique_module_reports_ambiguity() {
        let candidates = vec![module(), module()];
        let error = unique_module(candidates, "example.so", 42).expect_err("two matches");
        match error {
            Error::AmbiguousModuleName {
                pid,
                name,
                candidates,
            } => {
                assert_eq!(pid, 42);
                assert_eq!(name, "example.so");
                assert_eq!(candidates.len(), 2);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            unique_module(Vec::new(), "missing", 42)
                .expect("no match")
                .is_none()
        );
        assert!(
            unique_module(vec![module()], "example.so", 42)
                .expect("one match")
                .is_some()
        );
    }

    #[test]
    fn containment_skips_span_gaps() {
        let module = Module::from_raw(RawModule {
            name: "gapped.so".to_owned(),
            path: PathBuf::from("/usr/lib/gapped.so"),
            base: 0x1000,
            size: 0x2100,
            mappings: vec![(0x1000, 0x1100), (0x3000, 0x3100)],
        });
        assert!(module.contains(Address::new(0x1000)));
        assert!(module.contains(Address::new(0x10ff)));
        assert!(!module.contains(Address::new(0x1100)));
        assert!(!module.contains(Address::new(0x2fff)));
        assert!(module.contains(Address::new(0x3000)));
        assert_eq!(module.base(), Address::new(0x1000));
        assert_eq!(module.end(), Address::new(0x3100));
        assert_eq!(module.size(), 0x2100);
    }

    #[test]
    fn containment_is_half_open() {
        let module = module();
        assert!(module.contains(Address::new(0x4000)));
        assert!(module.contains(Address::new(0x4fff)));
        assert!(!module.contains(Address::new(0x5000)));
        assert!(!module.contains(Address::new(0x3fff)));
    }
}

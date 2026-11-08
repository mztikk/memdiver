//! Loaded executable modules.

use std::path::{Path, PathBuf};

use memdiver_sys::RawModule;

use crate::Address;

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
}

impl Module {
    pub(crate) fn from_raw(raw: RawModule) -> Self {
        Self {
            name: raw.name,
            path: raw.path,
            base: Address::new(raw.base),
            size: raw.size,
        }
    }

    /// Returns the module name reported by the platform.
    ///
    /// This is normally the file name. Linux file names that are not valid
    /// UTF-8 are converted lossily; use [`Module::path`] when the exact bytes
    /// matter.
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

    /// Returns the size of the module's mapping in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the first address after the module's mapping.
    ///
    /// The addition saturates at [`u64::MAX`].
    #[must_use]
    pub fn end(&self) -> Address {
        Address::new(self.base.get().saturating_add(self.size))
    }

    /// Returns `true` when `address` lies inside the module's mapping.
    #[must_use]
    pub fn contains(&self, address: Address) -> bool {
        address.get() >= self.base.get() && address.get() - self.base.get() < self.size
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

//! Module export resolution from PE and ELF files.

use std::collections::BTreeMap;

use goblin::elf::header::{ET_DYN, ET_EXEC};
use goblin::elf::sym::{
    STB_GLOBAL, STB_WEAK, STT_FUNC, STT_GNU_IFUNC, STT_OBJECT, STV_DEFAULT, STV_PROTECTED,
};

use crate::{Address, Error, Module, Process, Result};

/// A named symbol exported by a loaded module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    name: String,
    address: Address,
}

impl Export {
    /// Returns the exported symbol name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the symbol's address in the target process.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }
}

impl Process {
    /// Enumerates the named exports of a loaded module.
    ///
    /// Exports are parsed from the module file reported by the operating
    /// system, then converted to live addresses using the module's loaded base.
    /// PE forwarded exports and unnamed ordinal exports are skipped. On Linux,
    /// only defined dynamic symbols with default or protected visibility are
    /// returned; section headers must be present in the file for the ELF
    /// dynamic symbol table to be discoverable.
    ///
    /// The result is sorted by name (and address for duplicate names).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ModuleNotFound`] when the module is not loaded,
    /// [`Error::ModuleFile`] when its file cannot be read, or
    /// [`Error::ModuleExports`] when the file cannot be parsed.
    pub fn module_exports(&self, module: &str) -> Result<Vec<Export>> {
        let module = self.module(module)?.ok_or_else(|| Error::ModuleNotFound {
            name: module.to_owned(),
        })?;
        let path = module.path().to_path_buf();
        let bytes = std::fs::read(&path).map_err(|source| Error::ModuleFile {
            module: module.name().to_owned(),
            path: path.clone(),
            source,
        })?;
        parse_exports(&module, &bytes)
    }

    /// Looks up one named export of a loaded module.
    ///
    /// The name is matched exactly. PE forwarded exports and unnamed ordinal
    /// exports are not returned.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::module_exports`].
    pub fn module_export(&self, module: &str, name: &str) -> Result<Option<Address>> {
        Ok(self
            .module_exports(module)?
            .into_iter()
            .find(|export| export.name == name)
            .map(|export| export.address))
    }
}

fn parse_exports(module: &Module, bytes: &[u8]) -> Result<Vec<Export>> {
    let mut exports = if bytes.starts_with(b"\x7fELF") {
        let elf = goblin::elf::Elf::parse(bytes).map_err(|error| Error::ModuleExports {
            module: module.name().to_owned(),
            reason: error.to_string(),
        })?;
        elf_exports(module, &elf)?
    } else if bytes.starts_with(b"MZ") {
        let pe = goblin::pe::PE::parse(bytes).map_err(|error| Error::ModuleExports {
            module: module.name().to_owned(),
            reason: error.to_string(),
        })?;
        pe_exports(module, &pe)?
    } else {
        return Err(Error::ModuleExports {
            module: module.name().to_owned(),
            reason: "module file is neither ELF nor PE".to_owned(),
        });
    };
    exports.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.address.cmp(&right.address))
    });
    exports.dedup();
    Ok(exports)
}

fn elf_exports(module: &Module, elf: &goblin::elf::Elf<'_>) -> Result<Vec<Export>> {
    let base = module.base().get();
    let image_end = module.end().get();
    if elf.header.e_type != ET_DYN && elf.header.e_type != ET_EXEC {
        return Err(Error::ModuleExports {
            module: module.name().to_owned(),
            reason: format!(
                "ELF type {} is not a loaded executable or shared object",
                elf.header.e_type
            ),
        });
    }

    let mut exports = BTreeMap::new();
    for symbol in elf.dynsyms.iter() {
        if symbol.st_name == 0
            || symbol.st_shndx == 0
            || symbol.st_shndx >= 0xff00
            || symbol.st_value == 0
        {
            continue;
        }
        let bind = symbol.st_info >> 4;
        let symbol_type = symbol.st_info & 0x0f;
        let visibility = symbol.st_other & 0x03;
        let exported_binding = bind == STB_GLOBAL || bind == STB_WEAK;
        let exported_visibility = visibility == STV_DEFAULT || visibility == STV_PROTECTED;
        let exported_type =
            symbol_type == STT_FUNC || symbol_type == STT_OBJECT || symbol_type == STT_GNU_IFUNC;
        if !(exported_binding && exported_visibility && exported_type) {
            continue;
        }
        let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let Some(address) = elf_symbol_address(elf.header.e_type, base, symbol.st_value, image_end)
        else {
            continue;
        };
        exports.insert(name.to_owned(), Address::new(address));
    }
    Ok(exports
        .into_iter()
        .map(|(name, address)| Export { name, address })
        .collect())
}

fn pe_exports(module: &Module, pe: &goblin::pe::PE<'_>) -> Result<Vec<Export>> {
    let base = module.base().get();
    let image_end = module.end().get();
    let mut exports = BTreeMap::new();
    for export in &pe.exports {
        let Some(name) = export.name else {
            continue;
        };
        if name.is_empty() || export.rva == 0 || export.reexport.is_some() {
            continue;
        }
        let Ok(rva) = u64::try_from(export.rva) else {
            continue;
        };
        let Some(address) = pe_export_address(base, rva, image_end) else {
            continue;
        };
        exports.insert(name.to_owned(), Address::new(address));
    }
    Ok(exports
        .into_iter()
        .map(|(name, address)| Export { name, address })
        .collect())
}

fn elf_symbol_address(elf_type: u16, base: u64, symbol_value: u64, image_end: u64) -> Option<u64> {
    let load_bias = match elf_type {
        ET_DYN => base,
        ET_EXEC => 0,
        _ => return None,
    };
    let address = load_bias.checked_add(symbol_value)?;
    (address >= base && address < image_end).then_some(address)
}

fn pe_export_address(base: u64, rva: u64, image_end: u64) -> Option<u64> {
    let address = base.checked_add(rva)?;
    (address >= base && address < image_end).then_some(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebases_dynamic_elf_symbols() {
        assert_eq!(
            elf_symbol_address(ET_DYN, 0x7f00_0000_0000, 0x234, 0x7f00_0000_1000),
            Some(0x7f00_0000_0234)
        );
        assert_eq!(
            elf_symbol_address(ET_DYN, 0x7f00_0000_0000, 0x2000, 0x7f00_0000_1000),
            None
        );
    }

    #[test]
    fn keeps_absolute_exec_elf_symbols() {
        assert_eq!(
            elf_symbol_address(ET_EXEC, 0x0040_0000, 0x0040_1234, 0x0041_0000),
            Some(0x0040_1234)
        );
        assert_eq!(
            elf_symbol_address(ET_EXEC, 0x0040_0000, 0x003f_0000, 0x0041_0000),
            None
        );
    }

    #[test]
    fn rebases_pe_export_rvas() {
        assert_eq!(
            pe_export_address(0x1800_0000, 0x1234, 0x1800_2000),
            Some(0x1800_1234)
        );
        assert_eq!(pe_export_address(0x1800_0000, 0x2000, 0x1800_1000), None);
        assert_eq!(pe_export_address(u64::MAX - 1, 4, u64::MAX), None);
    }
}

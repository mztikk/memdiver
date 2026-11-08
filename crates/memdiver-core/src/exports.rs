//! Module export resolution from PE and ELF files.

use std::collections::BTreeMap;

use goblin::elf::header::{ET_DYN, ET_EXEC};
use goblin::elf::sym::{
    STB_GLOBAL, STB_WEAK, STT_FUNC, STT_GNU_IFUNC, STT_OBJECT, STV_DEFAULT, STV_PROTECTED,
};

use crate::process_info::name_matches;
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
    /// The module name is matched using the platform's process-name rules
    /// (case-sensitive on Linux, ASCII case-insensitive on Windows). If more
    /// than one loaded module has that name, [`Error::AmbiguousModuleName`] is
    /// returned with the candidates; use [`Process::module_exports_of`] to
    /// target a specific module.
    ///
    /// Exports are parsed from the module file reported by the operating
    /// system, then converted to live addresses using the module's loaded base.
    /// On Linux the file is opened through `/proc/<pid>/root`, so it is resolved
    /// in the target's mount namespace, and its inode must still match the
    /// mapping. The read is bounded to a regular file of at most
    /// [`memdiver_sys::MAX_MODULE_FILE_SIZE`] bytes; device files, FIFOs,
    /// oversized files and replaced files are rejected before parsing.
    ///
    /// PE forwarded exports and unnamed ordinal exports are skipped. On Linux,
    /// only defined dynamic symbols with default or protected visibility are
    /// returned; when several versions of a name exist, the default (non-hidden)
    /// symbol version is returned and compatibility versions are not listed
    /// separately. Section headers are not required to discover dynamic symbols,
    /// but version information (`versym`/`verdef`) is only available when the
    /// file still contains its version sections.
    ///
    /// The result is sorted by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ModuleNotFound`] when the module is not loaded,
    /// [`Error::AmbiguousModuleName`] when the name matches several modules,
    /// [`Error::ModuleFile`] when its file cannot be read, or
    /// [`Error::ModuleExports`]/[`Error::ModuleParse`] when the file cannot be
    /// parsed.
    pub fn module_exports(&self, module: &str) -> Result<Vec<Export>> {
        let module = self.find_module_for_exports(module)?;
        self.module_exports_of(&module)
    }

    /// Enumerates the named exports of a specific loaded module.
    ///
    /// This is the unambiguous form of [`Process::module_exports`]: it accepts
    /// the exact [`Module`] snapshot and can therefore target one of several
    /// modules with the same name. Prefer this method (and its result list)
    /// when resolving several export names, because each call re-reads and
    /// reparses the module file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ModuleFile`] when the module file cannot be read, or
    /// [`Error::ModuleExports`]/[`Error::ModuleParse`] when it cannot be
    /// parsed.
    pub fn module_exports_of(&self, module: &Module) -> Result<Vec<Export>> {
        let path = module.path();
        let bytes = self
            .inner
            .read_module_file(module.base().get(), path)
            .map_err(|source| Error::ModuleFile {
                module: module.name().to_owned(),
                path: path.to_path_buf(),
                source,
            })?;
        parse_exports(module, &bytes)
    }

    /// Looks up one named export of a loaded module.
    ///
    /// The module name follows the platform rules described on
    /// [`Process::module_exports`]; the export name is matched exactly. PE
    /// forwarded exports and unnamed ordinal exports are not returned. This
    /// call re-reads and reparses the module file; use
    /// [`Process::module_export_of`] or [`Process::module_exports_of`] when
    /// resolving several names from one module.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::module_exports`].
    pub fn module_export(&self, module: &str, name: &str) -> Result<Option<Address>> {
        let module = self.find_module_for_exports(module)?;
        self.module_export_of(&module, name)
    }

    /// Looks up one named export of a specific loaded module.
    ///
    /// The export name is matched exactly. This call still parses the whole
    /// export table; use [`Process::module_exports_of`] once when looking up
    /// several names.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::module_exports_of`].
    pub fn module_export_of(&self, module: &Module, name: &str) -> Result<Option<Address>> {
        Ok(self
            .module_exports_of(module)?
            .into_iter()
            .find(|export| export.name == name)
            .map(|export| export.address))
    }

    fn find_module_for_exports(&self, name: &str) -> Result<Module> {
        let candidates: Vec<Module> = self
            .modules()?
            .into_iter()
            .filter(|module| name_matches(module.name(), name))
            .collect();
        unique_module(candidates, name)
    }
}

/// Selects the one module matching `name`, or reports ambiguity.
fn unique_module(mut candidates: Vec<Module>, name: &str) -> Result<Module> {
    match candidates.len() {
        0 => Err(Error::ModuleNotFound {
            name: name.to_owned(),
        }),
        1 => Ok(candidates.pop().expect("one candidate")),
        _ => Err(Error::AmbiguousModuleName {
            name: name.to_owned(),
            candidates,
        }),
    }
}

fn parse_exports(module: &Module, bytes: &[u8]) -> Result<Vec<Export>> {
    if bytes.starts_with(b"\x7fELF") {
        let elf = goblin::elf::Elf::parse(bytes).map_err(|error| parse_error(module, error))?;
        elf_exports(module, &elf)
    } else if bytes.starts_with(b"MZ") {
        let pe = goblin::pe::PE::parse(bytes).map_err(|error| parse_error(module, error))?;
        if pe_has_export_directory(&pe) && pe.export_data.is_none() {
            return Err(Error::ModuleExports {
                module: module.name().to_owned(),
                reason: "the PE export directory is present but could not be parsed".to_owned(),
            });
        }
        pe_exports(module, &pe)
    } else {
        Err(Error::ModuleExports {
            module: module.name().to_owned(),
            reason: "module file is neither ELF nor PE".to_owned(),
        })
    }
}

fn parse_error(module: &Module, error: goblin::error::Error) -> Error {
    Error::ModuleParse {
        module: module.name().to_owned(),
        reason: error.to_string(),
        source: Box::new(error),
    }
}

fn pe_has_export_directory(pe: &goblin::pe::PE<'_>) -> bool {
    pe.header
        .optional_header
        .as_ref()
        .and_then(|header| header.data_directories.get_export_table())
        .is_some_and(|directory| directory.virtual_address != 0 && directory.size != 0)
}

/// Inserts one symbol, preferring the default (non-hidden) version of a name.
///
/// ELF dynamic symbol tables can contain several symbols with one name: the
/// default version and compatibility versions. `versym` marks compatibility
/// versions as hidden. The `BTreeMap` is keyed by name so callers see one
/// address per name; the default version wins regardless of symbol-table
/// order. If version information is unavailable, the first symbol in table
/// order wins, which matches the usual default-first layout.
fn insert_default_export(
    exports: &mut BTreeMap<String, (bool, Address)>,
    name: &str,
    address: Address,
    hidden: bool,
) {
    match exports.entry(name.to_owned()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert((hidden, address));
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            if entry.get().0 && !hidden {
                entry.insert((hidden, address));
            }
        }
    }
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
    for (index, symbol) in elf.dynsyms.iter().enumerate() {
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
        let hidden = elf
            .versym
            .as_ref()
            .and_then(|versym| versym.get_at(index))
            .is_some_and(|version| version.is_hidden());
        insert_default_export(&mut exports, name, Address::new(address), hidden);
    }
    Ok(exports
        .into_iter()
        .map(|(name, (_, address))| Export { name, address })
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
        insert_default_export(&mut exports, name, Address::new(address), false);
    }
    Ok(exports
        .into_iter()
        .map(|(name, (_, address))| Export { name, address })
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

    fn test_module() -> Module {
        Module::from_raw(memdiver_sys::RawModule {
            name: "test.so".to_owned(),
            path: std::path::PathBuf::from("/test.so"),
            base: 0x1000,
            size: 0x1000,
        })
    }

    fn raw_module(name: &str, base: u64) -> Module {
        Module::from_raw(memdiver_sys::RawModule {
            name: name.to_owned(),
            path: std::path::PathBuf::from(format!("/{name}")),
            base,
            size: 0x1000,
        })
    }

    #[test]
    fn duplicate_module_names_are_ambiguous() {
        let candidates = vec![
            raw_module("libfoo.so", 0x1000),
            raw_module("libfoo.so", 0x2000),
        ];
        let error = unique_module(candidates, "libfoo.so").expect_err("duplicate names");
        match error {
            Error::AmbiguousModuleName { name, candidates } => {
                assert_eq!(name, "libfoo.so");
                assert_eq!(candidates.len(), 2);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// A minimal PE32+ image whose export data directory points outside the
    /// file. Goblin parses the image but silently drops the malformed export
    /// table, which is exactly the case the library must report.
    fn pe_with_corrupt_export_directory() -> Vec<u8> {
        fn put16(bytes: &mut [u8], offset: usize, value: u16) {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn put32(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn put64(bytes: &mut [u8], offset: usize, value: u64) {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        put32(&mut pe, 0x3c, 0x40);
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        put16(&mut pe, 0x44, 0x8664); // machine
        put16(&mut pe, 0x46, 1); // sections
        put16(&mut pe, 0x54, 0xF0); // optional header size
        put16(&mut pe, 0x56, 0x22); // characteristics

        let optional = 0x58;
        put16(&mut pe, optional, 0x20B); // PE32+
        put32(&mut pe, optional + 4, 0x200); // size of code
        put32(&mut pe, optional + 16, 0x1000); // entry point
        put32(&mut pe, optional + 20, 0x1000); // base of code
        put64(&mut pe, optional + 24, 0x1_4000_0000); // image base
        put32(&mut pe, optional + 32, 0x1000); // section alignment
        put32(&mut pe, optional + 36, 0x200); // file alignment
        put16(&mut pe, optional + 40, 6);
        put16(&mut pe, optional + 48, 6);
        put32(&mut pe, optional + 56, 0x2000); // size of image
        put32(&mut pe, optional + 60, 0x200); // size of headers
        put16(&mut pe, optional + 68, 3); // console subsystem
        put64(&mut pe, optional + 72, 0x10_0000);
        put64(&mut pe, optional + 80, 0x1000);
        put64(&mut pe, optional + 88, 0x10_0000);
        put64(&mut pe, optional + 96, 0x1000);
        put32(&mut pe, optional + 108, 16); // data directories
        put32(&mut pe, optional + 112, 0x1500); // export RVA (outside file)
        put32(&mut pe, optional + 116, 0x28);

        let section = 0x178;
        pe[section..section + 5].copy_from_slice(b".text");
        put32(&mut pe, section + 8, 0x1000);
        put32(&mut pe, section + 12, 0x1000);
        put32(&mut pe, section + 16, 0x200);
        put32(&mut pe, section + 20, 0x200);
        put32(&mut pe, section + 36, 0x6000_0020);
        pe
    }

    #[test]
    fn corrupt_pe_export_directory_is_an_error() {
        let module = test_module();
        let error = parse_exports(&module, &pe_with_corrupt_export_directory())
            .expect_err("a present but malformed export directory must fail");
        match error {
            Error::ModuleExports { reason, .. } => {
                assert!(reason.contains("export directory"), "{reason}");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn malformed_formats_keep_the_parser_source() {
        use std::error::Error as _;

        let module = test_module();
        let error = parse_exports(&module, b"\x7fELF not actually an ELF file")
            .expect_err("malformed ELF must fail");
        assert!(matches!(error, Error::ModuleParse { .. }), "{error:?}");
        assert!(
            error.source().is_some(),
            "the goblin parser error must be the source"
        );

        let error =
            parse_exports(&module, b"not an executable").expect_err("unknown format must fail");
        assert!(matches!(error, Error::ModuleExports { .. }), "{error:?}");
        assert!(error.source().is_none());
    }

    #[test]
    fn prefers_the_default_symbol_version() {
        let mut exports = BTreeMap::new();
        // Compatibility version appears first, default version second.
        insert_default_export(&mut exports, "sym", Address::new(0xaa090), true);
        insert_default_export(&mut exports, "sym", Address::new(0xab260), false);
        assert_eq!(exports["sym"].1, Address::new(0xab260));
        assert!(!exports["sym"].0);

        // Default first, compatibility second: the default must not be replaced.
        let mut exports = BTreeMap::new();
        insert_default_export(&mut exports, "sym", Address::new(0xab260), false);
        insert_default_export(&mut exports, "sym", Address::new(0xaa090), true);
        assert_eq!(exports["sym"].1, Address::new(0xab260));

        // Without version information the first symbol-table entry wins.
        let mut exports = BTreeMap::new();
        insert_default_export(&mut exports, "sym", Address::new(0x1000), false);
        insert_default_export(&mut exports, "sym", Address::new(0x2000), false);
        assert_eq!(exports["sym"].1, Address::new(0x1000));
    }

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

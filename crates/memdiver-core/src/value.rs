//! Typed value scanning.

use bytemuck::Pod;

use crate::{Address, Pattern, Process, Result, ScanOptions};

impl Process {
    /// Finds all occurrences of a typed value in readable memory.
    ///
    /// The value is encoded in native byte order and scanned with the supplied
    /// options. Set [`ScanOptions::with_alignment`] to the type's alignment (or
    /// its size) to avoid unaligned false positives. Zero-sized values cannot
    /// be scanned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPattern`](crate::Error::InvalidPattern) for a
    /// zero-sized value, or the same errors as [`Process::find_patterns`].
    pub fn find_values<T: Pod>(&self, value: T, options: &ScanOptions) -> Result<Vec<Address>> {
        let pattern = Pattern::from_exact_bytes(bytemuck::bytes_of(&value))?;
        self.find_patterns(&pattern, options)
    }

    /// Finds all occurrences of a typed value in loaded modules.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::find_values`] and
    /// [`Process::find_patterns_in_modules`].
    pub fn find_values_in_modules<T: Pod>(
        &self,
        value: T,
        options: &ScanOptions,
    ) -> Result<Vec<Address>> {
        let pattern = Pattern::from_exact_bytes(bytemuck::bytes_of(&value))?;
        self.find_patterns_in_modules(&pattern, options)
    }

    /// Finds all occurrences of a typed value in one named module.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::find_values`] and
    /// [`Process::find_patterns_in_module`].
    pub fn find_values_in_module<T: Pod>(
        &self,
        module: &str,
        value: T,
        options: &ScanOptions,
    ) -> Result<Vec<Address>> {
        let pattern = Pattern::from_exact_bytes(bytemuck::bytes_of(&value))?;
        self.find_patterns_in_module(module, &pattern, options)
    }
}

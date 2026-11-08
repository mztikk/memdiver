//! Batched memory transfers.

use crate::{Address, Error, Process, Result};

impl Process {
    /// Reads several independent ranges in order.
    ///
    /// Entries are processed sequentially. If an entry fails, the returned
    /// [`Error::BatchRead`] carries its index and the full underlying error;
    /// results for previous entries are discarded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BatchRead`] when any entry fails.
    pub fn read_many(&self, ranges: &[(Address, usize)]) -> Result<Vec<Vec<u8>>> {
        let mut results = Vec::new();
        results
            .try_reserve(ranges.len())
            .map_err(|source| Error::Allocation {
                len: ranges.len().saturating_mul(std::mem::size_of::<Vec<u8>>()),
                source,
            })?;
        for (index, (address, len)) in ranges.iter().enumerate() {
            let bytes = self
                .read_bytes(*address, *len)
                .map_err(|source| Error::BatchRead {
                    index,
                    address: *address,
                    len: *len,
                    source: Box::new(source),
                })?;
            results.push(bytes);
        }
        Ok(results)
    }

    /// Writes several independent buffers in order.
    ///
    /// Entries are processed sequentially. If an entry fails, the returned
    /// [`Error::BatchWrite`] carries its index and the full underlying error.
    /// Earlier entries may already have been written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReadOnly`] when the handle is read-only and at least one
    /// entry is non-empty, or [`Error::BatchWrite`] when an entry fails.
    pub fn write_many(&self, writes: &[(Address, &[u8])]) -> Result<()> {
        if !self.is_writable() && writes.iter().any(|(_, data)| !data.is_empty()) {
            return Err(Error::ReadOnly {
                pid: self.pid,
                operation: "Process::write_many",
            });
        }
        for (index, (address, data)) in writes.iter().enumerate() {
            self.write(*address, data)
                .map_err(|source| Error::BatchWrite {
                    index,
                    address: *address,
                    len: data.len(),
                    source: Box::new(source),
                })?;
        }
        Ok(())
    }
}

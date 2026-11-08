//! Bounded string reads.

use memchr::memchr;

use crate::{Address, Error, Process, Result};

const STRING_CHUNK_BYTES: usize = 256;

impl Process {
    /// Reads a NUL-terminated byte string.
    ///
    /// At most `max_bytes` bytes are read. The returned bytes exclude the NUL
    /// terminator. If no NUL is found within the limit, the limit-sized prefix
    /// is returned; callers that need to distinguish truncation can compare the
    /// returned length with `max_bytes`.
    ///
    /// # Errors
    ///
    /// Returns read errors for inaccessible memory, [`Error::AddressRange`]
    /// when the range wraps, or [`Error::Allocation`] when the result cannot be
    /// grown.
    pub fn read_c_string(&self, address: Address, max_bytes: usize) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut offset = 0usize;
        while offset < max_bytes {
            let chunk_len = STRING_CHUNK_BYTES.min(max_bytes - offset);
            let current = address
                .checked_add(offset as u64)
                .ok_or(Error::AddressRange {
                    address,
                    len: max_bytes,
                })?;
            let chunk = self.read_bytes(current, chunk_len)?;
            let found = memchr(0, &chunk);
            let append_len = found.unwrap_or(chunk.len());
            result
                .try_reserve(append_len)
                .map_err(|source| Error::Allocation {
                    len: max_bytes,
                    source,
                })?;
            result.extend_from_slice(&chunk[..append_len]);
            if found.is_some() {
                return Ok(result);
            }
            offset += chunk_len;
        }
        Ok(result)
    }

    /// Reads a NUL-terminated byte string and decodes it as UTF-8 lossily.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Process::read_c_string`].
    pub fn read_c_string_lossy(&self, address: Address, max_bytes: usize) -> Result<String> {
        let bytes = self.read_c_string(address, max_bytes)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Reads a NUL-terminated UTF-16LE string.
    ///
    /// At most `max_units` UTF-16 code units are read. The returned string
    /// excludes the terminator and is decoded lossily, replacing unpaired
    /// surrogates. If no terminator is found within the limit, the prefix is
    /// decoded and returned.
    ///
    /// # Errors
    ///
    /// Returns read errors for inaccessible memory, [`Error::AddressRange`]
    /// when the range wraps, or [`Error::Allocation`] when the result cannot be
    /// grown.
    pub fn read_utf16_string(&self, address: Address, max_units: usize) -> Result<String> {
        let mut units = Vec::new();
        let mut offset_units = 0usize;
        while offset_units < max_units {
            let chunk_units = STRING_CHUNK_BYTES.min(max_units - offset_units);
            let byte_offset = offset_units
                .checked_mul(2)
                .and_then(|offset| u64::try_from(offset).ok())
                .ok_or(Error::AddressRange {
                    address,
                    len: max_units,
                })?;
            let current = address
                .checked_add(byte_offset)
                .ok_or(Error::AddressRange {
                    address,
                    len: max_units,
                })?;
            let byte_len = chunk_units.checked_mul(2).ok_or(Error::AddressRange {
                address,
                len: max_units,
            })?;
            let chunk = self.read_bytes(current, byte_len)?;
            units
                .try_reserve(chunk_units)
                .map_err(|source| Error::Allocation {
                    len: max_units,
                    source,
                })?;
            for pair in chunk.chunks_exact(2) {
                let unit = u16::from_le_bytes([pair[0], pair[1]]);
                if unit == 0 {
                    return Ok(String::from_utf16_lossy(&units));
                }
                units.push(unit);
            }
            offset_units += chunk_units;
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

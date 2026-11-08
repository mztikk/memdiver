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
    /// returned length with `max_bytes`. If a chunk run crosses into
    /// inaccessible memory, the readable prefix is returned instead of failing
    /// when the terminator was already in the readable part.
    ///
    /// # Errors
    ///
    /// Returns read errors for inaccessible memory, [`Error::AddressRange`]
    /// when the range wraps, or [`Error::Allocation`] when the result cannot be
    /// grown. A first chunk that transfers zero bytes is an error.
    pub fn read_c_string(&self, address: Address, max_bytes: usize) -> Result<Vec<u8>> {
        read_c_string_with(self.pid, address, max_bytes, |address, buffer| {
            self.read(address, buffer)
        })
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
    /// decoded and returned. If a chunk crosses into inaccessible memory, the
    /// readable prefix is returned.
    ///
    /// # Errors
    ///
    /// Returns read errors for inaccessible memory, [`Error::AddressRange`]
    /// when the range wraps, or [`Error::Allocation`] when the result cannot be
    /// grown. A first chunk that transfers zero bytes is an error.
    pub fn read_utf16_string(&self, address: Address, max_units: usize) -> Result<String> {
        read_utf16_string_with(self.pid, address, max_units, |address, buffer| {
            self.read(address, buffer)
        })
    }
}

fn read_c_string_with<F>(
    pid: u32,
    address: Address,
    max_bytes: usize,
    mut read: F,
) -> Result<Vec<u8>>
where
    F: FnMut(Address, &mut [u8]) -> Result<()>,
{
    let mut result = Vec::new();
    let mut offset = 0usize;
    let mut buffer = [0u8; STRING_CHUNK_BYTES];

    while offset < max_bytes {
        let chunk_len = STRING_CHUNK_BYTES.min(max_bytes - offset);
        let current = address
            .checked_add(offset as u64)
            .ok_or(Error::AddressRange {
                pid,
                address,
                len: max_bytes,
            })?;
        let filled = match read(current, &mut buffer[..chunk_len]) {
            Ok(()) => chunk_len,
            // A partial transfer means the mapping ended inside this chunk.
            // Keep the readable prefix; the terminator may be in it.
            Err(Error::PartialRead { transferred, .. })
                if transferred > 0 && transferred <= chunk_len =>
            {
                transferred
            }
            Err(error) => return Err(error),
        };
        let chunk = &buffer[..filled];
        if let Some(position) = memchr(0, chunk) {
            result
                .try_reserve(position)
                .map_err(|source| Error::Allocation {
                    len: position,
                    source,
                })?;
            result.extend_from_slice(&chunk[..position]);
            return Ok(result);
        }
        result
            .try_reserve(filled)
            .map_err(|source| Error::Allocation {
                len: filled,
                source,
            })?;
        result.extend_from_slice(chunk);
        if filled < chunk_len {
            // The rest of the chunk is inaccessible and no terminator was in
            // the readable part; return the truncated prefix.
            return Ok(result);
        }
        offset += chunk_len;
    }
    Ok(result)
}

fn read_utf16_string_with<F>(
    pid: u32,
    address: Address,
    max_units: usize,
    mut read: F,
) -> Result<String>
where
    F: FnMut(Address, &mut [u8]) -> Result<()>,
{
    let mut units = Vec::new();
    let mut offset_units = 0usize;
    let mut buffer = [0u8; STRING_CHUNK_BYTES];

    while offset_units < max_units {
        let remaining_units = max_units - offset_units;
        let chunk_units = (STRING_CHUNK_BYTES / 2).min(remaining_units);
        let byte_offset = offset_units
            .checked_mul(2)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(Error::AddressRange {
                pid,
                address,
                len: max_units,
            })?;
        let current = address
            .checked_add(byte_offset)
            .ok_or(Error::AddressRange {
                pid,
                address,
                len: max_units,
            })?;
        let byte_len = chunk_units.checked_mul(2).ok_or(Error::AddressRange {
            pid,
            address,
            len: max_units,
        })?;
        let filled = match read(current, &mut buffer[..byte_len]) {
            Ok(()) => byte_len,
            Err(Error::PartialRead { transferred, .. })
                if transferred > 0 && transferred <= byte_len =>
            {
                transferred
            }
            Err(error) => return Err(error),
        };

        // A partial transfer can end on an odd byte; only whole UTF-16 units
        // are meaningful.
        let complete_units = filled / 2;
        units
            .try_reserve(complete_units)
            .map_err(|source| Error::Allocation {
                len: complete_units.saturating_mul(2),
                source,
            })?;
        for pair in buffer[..complete_units * 2].chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            if unit == 0 {
                return Ok(String::from_utf16_lossy(&units));
            }
            units.push(unit);
        }
        if filled < byte_len {
            return Ok(String::from_utf16_lossy(&units));
        }
        offset_units += chunk_units;
    }
    Ok(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x2000;

    /// Copies the readable prefix and reports a short transfer at `limit`.
    fn bounded_read(
        data: &'static [u8],
        limit: usize,
    ) -> impl FnMut(Address, &mut [u8]) -> Result<()> {
        move |address, buffer| {
            let offset = usize::try_from(address.get() - BASE).expect("offset");
            let available = data.len().saturating_sub(offset).min(limit);
            buffer[..available].copy_from_slice(&data[offset..offset + available]);
            if available < buffer.len() {
                Err(Error::PartialRead {
                    pid: 1,
                    address,
                    requested: buffer.len(),
                    transferred: available,
                })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn c_string_at_mapping_end_keeps_the_terminator() {
        // The chunk is 256 bytes but only 8 are mapped; the NUL is at byte 3.
        let mut read = bounded_read(b"abc\0xxxx", 8);
        let value = read_c_string_with(1, Address::new(BASE), 64, &mut read).expect("string");
        assert_eq!(value, b"abc");
    }

    #[test]
    fn c_string_without_terminator_returns_the_readable_prefix() {
        let mut read = bounded_read(b"abcdefgh", 8);
        let value = read_c_string_with(1, Address::new(BASE), 64, &mut read).expect("prefix");
        assert_eq!(value, b"abcdefgh");
    }

    #[test]
    fn c_string_with_zero_first_transfer_is_an_error() {
        let mut read = bounded_read(b"", 0);
        let error = read_c_string_with(1, Address::new(BASE), 64, &mut read)
            .expect_err("an inaccessible first chunk must fail");
        assert!(matches!(error, Error::PartialRead { .. }));
    }

    #[test]
    fn utf16_string_at_mapping_end_keeps_the_terminator() {
        // "ab\0" in UTF-16LE plus the start of the next unit, but only 6 bytes
        // are readable (three complete units).
        let data: &'static [u8] = &[b'a', 0, b'b', 0, 0, 0, b'x', 0];
        let mut read = bounded_read(data, 6);
        let value = read_utf16_string_with(1, Address::new(BASE), 8, &mut read).expect("string");
        assert_eq!(value, "ab");
    }

    #[test]
    fn utf16_string_without_terminator_returns_complete_units() {
        let data: &'static [u8] = &[b'a', 0, b'b', 0, b'c', 0];
        let mut read = bounded_read(data, 5); // partial final unit
        let value = read_utf16_string_with(1, Address::new(BASE), 8, &mut read).expect("prefix");
        assert_eq!(value, "ab");
    }
}

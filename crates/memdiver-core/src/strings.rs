//! Bounded string reads.

use memchr::memchr;
use memdiver_sys::ErrorKind as OsErrorKind;

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
    /// If a later chunk cannot be read because the mapping ended, the bytes read
    /// so far are returned (with or without a partial-transfer count). A read
    /// failure on the first chunk is an error, as are address-space
    /// replacement, process exit, range overflow and allocation failure.
    ///
    /// # Errors
    ///
    /// Returns read errors for an inaccessible first chunk,
    /// [`Error::AddressSpaceReplaced`] or a process exit anywhere in the string,
    /// [`Error::AddressRange`] when the range wraps, or [`Error::Allocation`]
    /// when the result cannot be grown.
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
    /// decoded and returned. If a later chunk cannot be read because the
    /// mapping ended, the units read so far are returned; a read failure on the
    /// first chunk is an error.
    ///
    /// # Errors
    ///
    /// Returns read errors for an inaccessible first chunk,
    /// [`Error::AddressSpaceReplaced`] or a process exit anywhere in the string,
    /// [`Error::AddressRange`] when the range wraps, or [`Error::Allocation`]
    /// when the result cannot be grown.
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
            Err(error) => {
                // A later chunk that cannot be read means the readable run
                // ended; return what was read so far. A fatal error (process
                // exit, replaced address space, overflow or allocation) is
                // always propagated.
                if offset > 0 && !string_read_aborts(&error) {
                    return Ok(result);
                }
                return Err(error);
            }
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
            Err(error) => {
                if offset_units > 0 && !string_read_aborts(&error) {
                    return Ok(String::from_utf16_lossy(&units));
                }
                return Err(error);
            }
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

/// Returns `true` when a failed string chunk must abort the whole read rather
/// than being treated as the end of the readable mapping.
fn string_read_aborts(error: &Error) -> bool {
    match error {
        Error::AddressSpaceReplaced { .. } => true,
        Error::Read { source, .. } => matches!(source.kind(), OsErrorKind::ProcessExited),
        Error::AddressRange { .. } | Error::Allocation { .. } => true,
        _ => false,
    }
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
    fn c_string_later_chunk_failure_returns_the_readable_prefix() {
        let mut read = |address: Address, buffer: &mut [u8]| {
            if address.get() == BASE {
                buffer.fill(b'x');
                Ok(())
            } else {
                Err(Error::PartialRead {
                    pid: 1,
                    address,
                    requested: buffer.len(),
                    transferred: 0,
                })
            }
        };
        let value = read_c_string_with(1, Address::new(BASE), STRING_CHUNK_BYTES * 2, &mut read)
            .expect("later inaccessible chunk returns the prefix");
        assert_eq!(value, vec![b'x'; STRING_CHUNK_BYTES]);
    }

    #[test]
    fn c_string_later_chunk_fatal_error_is_propagated() {
        let mut read = |address: Address, buffer: &mut [u8]| {
            if address.get() == BASE {
                buffer.fill(b'x');
                Ok(())
            } else {
                Err(Error::AddressSpaceReplaced {
                    pid: 1,
                    address,
                    len: buffer.len(),
                })
            }
        };
        let error = read_c_string_with(1, Address::new(BASE), STRING_CHUNK_BYTES * 2, &mut read)
            .expect_err("a replaced address space must abort");
        assert!(matches!(error, Error::AddressSpaceReplaced { .. }));
    }

    #[test]
    fn utf16_string_later_chunk_failure_returns_complete_units() {
        let mut read = |address: Address, buffer: &mut [u8]| {
            if address.get() == BASE {
                for unit in buffer.chunks_exact_mut(2) {
                    unit.copy_from_slice(&u16::from(b'a').to_le_bytes());
                }
                Ok(())
            } else {
                Err(Error::PartialRead {
                    pid: 1,
                    address,
                    requested: buffer.len(),
                    transferred: 0,
                })
            }
        };
        let units = (STRING_CHUNK_BYTES / 2) * 2;
        let value = read_utf16_string_with(1, Address::new(BASE), units, &mut read)
            .expect("later inaccessible chunk returns the units");
        assert_eq!(value, "a".repeat(STRING_CHUNK_BYTES / 2));
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

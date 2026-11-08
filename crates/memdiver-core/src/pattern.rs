//! Byte-pattern parsing and scanning options.

use crate::{Error, Result};

const MAX_PATTERN_LEN: usize = 1024 * 1024;

/// A byte pattern with wildcard support, in IDA-style notation.
///
/// Tokens are whitespace-separated and exactly two characters long (a lone `?`
/// is also accepted as a full wildcard):
///
/// ```text
/// 48 8B 05 ?? ?? ?? ??   exact bytes with full wildcards
/// 4? 8? 0?              high nibble fixed, low nibble wildcard
/// ?F 8B                 high nibble wildcard, low nibble fixed
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<u8>,
    masks: Vec<u8>,
    anchor: Option<(usize, u8)>,
}

impl Pattern {
    /// Parses a textual pattern.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPattern`] for an empty pattern, a token with the
    /// wrong shape, a non-hexadecimal nibble, or a pattern longer than one
    /// mebibyte.
    pub fn parse(text: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        let mut masks = Vec::new();
        let mut anchor = None;

        for (index, token) in text.split_whitespace().enumerate() {
            let (byte, mask) = parse_token(token).map_err(|reason| Error::InvalidPattern {
                reason: format!("token {} ({token:?}): {reason}", index + 1),
            })?;
            if anchor.is_none() && mask == 0xFF {
                anchor = Some((bytes.len(), byte));
            }
            bytes.push(byte);
            masks.push(mask);
        }

        if bytes.is_empty() {
            return Err(Error::InvalidPattern {
                reason: "pattern must contain at least one byte".to_owned(),
            });
        }
        if bytes.len() > MAX_PATTERN_LEN {
            return Err(Error::InvalidPattern {
                reason: format!("pattern is longer than {MAX_PATTERN_LEN} bytes"),
            });
        }

        Ok(Self {
            bytes,
            masks,
            anchor,
        })
    }

    /// Returns the number of bytes in the pattern.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when the pattern is empty.
    ///
    /// Parsed patterns are never empty; this exists for completeness.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn anchor(&self) -> Option<(usize, u8)> {
        self.anchor
    }

    pub(crate) fn matches_at(&self, haystack: &[u8]) -> bool {
        if haystack.len() < self.bytes.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(&self.masks)
            .zip(haystack)
            .all(|((expected, mask), actual)| actual & mask == expected & mask)
    }
}

fn parse_token(token: &str) -> std::result::Result<(u8, u8), String> {
    if token == "?" {
        return Ok((0, 0));
    }
    if !token.is_ascii() || token.len() != 2 {
        return Err("expected two hexadecimal nibbles or '?' wildcards".to_owned());
    }
    let bytes = token.as_bytes();
    let high = nibble(bytes[0])?;
    let low = nibble(bytes[1])?;
    match (high, low) {
        (Some(high), Some(low)) => Ok(((high << 4) | low, 0xFF)),
        (Some(high), None) => Ok((high << 4, 0xF0)),
        (None, Some(low)) => Ok((low, 0x0F)),
        (None, None) => Ok((0, 0)),
    }
}

fn nibble(byte: u8) -> std::result::Result<Option<u8>, String> {
    match byte {
        b'0'..=b'9' => Ok(Some(byte - b'0')),
        b'a'..=b'f' => Ok(Some(byte - b'a' + 10)),
        b'A'..=b'F' => Ok(Some(byte - b'A' + 10)),
        b'?' => Ok(None),
        other => Err(format!("{other:?} is not a hexadecimal digit or '?'")),
    }
}

/// Options controlling a memory scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanOptions {
    alignment: usize,
    max_results: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            alignment: 1,
            max_results: 1024,
        }
    }
}

impl ScanOptions {
    /// Creates default scan options: byte alignment and at most 1024 hits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the required alignment of a match's address.
    ///
    /// A value of `0` is normalized to `1`. Alignment is applied to the
    /// absolute target address, not to the region offset.
    #[must_use]
    pub fn with_alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment.max(1);
        self
    }

    /// Sets the maximum number of hits (`0` means unlimited).
    ///
    /// Unlimited scans can allocate a large result vector; prefer a bound for
    /// broad scans. [`Process::find_pattern`](crate::Process::find_pattern)
    /// always stops at the first hit.
    #[must_use]
    pub fn with_max_results(mut self, max_results: usize) -> Self {
        self.max_results = max_results;
        self
    }

    /// Returns the required address alignment.
    #[must_use]
    pub fn alignment(&self) -> usize {
        self.alignment
    }

    /// Returns the maximum number of hits, or `0` for unlimited.
    #[must_use]
    pub fn max_results(&self) -> usize {
        self.max_results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_and_wildcard_bytes() {
        let pattern = Pattern::parse("48 8B 05 ?? 4? ?F A?").expect("valid pattern");
        assert_eq!(pattern.len(), 7);
        assert_eq!(pattern.anchor(), Some((0, 0x48)));
        assert!(pattern.matches_at(&[0x48, 0x8B, 0x05, 0xAA, 0x4F, 0x3F, 0xA1]));
        assert!(pattern.matches_at(&[0x48, 0x8B, 0x05, 0x00, 0x4A, 0xFF, 0xAF]));
        assert!(!pattern.matches_at(&[0x48, 0x8B, 0x05, 0xAA, 0x5F, 0x3F, 0xA1]));
    }

    #[test]
    fn lone_question_mark_is_a_full_wildcard() {
        let pattern = Pattern::parse("AA ? BB").expect("valid pattern");
        assert!(pattern.matches_at(&[0xAA, 0x42, 0xBB]));
    }

    #[test]
    fn rejects_empty_and_malformed_patterns() {
        for text in ["", "   ", "4", "GG", "123", "4 8"] {
            let error = Pattern::parse(text).expect_err("must reject");
            assert!(
                matches!(error, Error::InvalidPattern { .. }),
                "{text:?}: {error:?}"
            );
        }
    }

    #[test]
    fn rejects_oversized_patterns() {
        let text = "AA ".repeat(MAX_PATTERN_LEN + 1);
        assert!(matches!(
            Pattern::parse(&text),
            Err(Error::InvalidPattern { .. })
        ));
    }

    #[test]
    fn options_are_chainable() {
        let options = ScanOptions::new().with_alignment(0).with_max_results(7);
        assert_eq!(options.alignment(), 1);
        assert_eq!(options.max_results(), 7);
        assert_eq!(ScanOptions::default().alignment(), 1);
    }
}

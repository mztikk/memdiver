//! Child process used by the end-to-end tests.
//!
//! The fixture allocates a deterministic 4 KiB buffer, prints its address and
//! then waits for commands on stdin. It never reads or writes the buffer while
//! the parent is accessing it, so the tests exercise the real cross-process
//! memory APIs without racing the fixture's own accesses.
//!
//! Protocol (one command per line):
//!
//! * `READY <pid> <address> <length>` — first line written by the fixture.
//! * `PING` → `PONG`
//! * `PEEK <offset> <length>` → lowercase hexadecimal bytes
//! * `EXIT` → the fixture exits
//!
//! Invalid commands or ranges produce `ERR`.

use std::fmt::Write as _;
use std::io::{self, BufRead, Write};

const BUFFER_LEN: usize = 4096;
const MULTIPLIER: u8 = 37;
const ADDEND: u8 = 11;

/// Keep this byte-for-byte in sync with `MODULE_SIGNATURE` in the test harness.
#[used]
static MODULE_SIGNATURE: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0x6D, 0x65, 0x6D, 0x64, 0x69, 0x76, 0x65, 0x72, 0x21, 0x7F, 0x3C, 0x9A,
];

fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(MULTIPLIER).wrapping_add(ADDEND))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn main() -> io::Result<()> {
    // Force the signature into the image's read-only data so pattern scans that
    // enumerate modules can find it.
    std::hint::black_box(&MODULE_SIGNATURE);

    let buffer = pattern(BUFFER_LEN);
    let stdout = io::stdout();
    let mut output = stdout.lock();

    writeln!(
        output,
        "READY {} {} {}",
        std::process::id(),
        buffer.as_ptr() as usize,
        buffer.len()
    )?;
    output.flush()?;

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("PING") => writeln!(output, "PONG")?,
            Some("PEEK") => {
                let offset = fields.next().and_then(|value| value.parse::<usize>().ok());
                let len = fields.next().and_then(|value| value.parse::<usize>().ok());
                match (offset, len) {
                    (Some(offset), Some(len)) => {
                        let range = offset
                            .checked_add(len)
                            .and_then(|end| buffer.get(offset..end));
                        match range {
                            Some(bytes) => writeln!(output, "{}", hex(bytes))?,
                            None => writeln!(output, "ERR")?,
                        }
                    }
                    _ => writeln!(output, "ERR")?,
                }
            }
            Some("EXIT") => break,
            Some(_) | None => writeln!(output, "ERR")?,
        }
        output.flush()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_is_deterministic_and_wraps() {
        let bytes = pattern(300);
        assert_eq!(bytes[0], ADDEND);
        assert_eq!(bytes[1], MULTIPLIER.wrapping_add(ADDEND));
        assert_eq!(
            bytes[255],
            255u8.wrapping_mul(MULTIPLIER).wrapping_add(ADDEND)
        );
        assert_eq!(bytes.len(), 300);
    }

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
        assert_eq!(hex(&[]), "");
    }
}

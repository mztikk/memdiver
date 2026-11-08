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
//! * `CODE` → `CODE <address> <length>` for the executable code target
//! * `MULTI` (Windows only) → `MULTI <address> <length> <page_size>` for the
//!   two-page allocation with differing protections
//! * `ZERO` (Linux only) → `ZERO <address>` for an executable `/dev/zero`
//!   mapping used to test device-backed module rejection
//! * `EXEC` (Linux only) — replaces the fixture image with itself; the parent's
//!   pinned memory descriptor becomes stale
//! * `EXIT` → the fixture exits
//!
//! Invalid commands or ranges produce `ERR`.

use std::fmt::Write as _;
use std::io::{self, BufRead, Write};

const BUFFER_LEN: usize = 4096;
const MULTIPLIER: u8 = 37;
const ADDEND: u8 = 11;

/// Number of executable bytes exposed by the `CODE` command.
///
/// The parent writes these bytes back unchanged, so a failed protection
/// restore cannot change the fixture's behaviour.
const CODE_LEN: usize = 4;

/// A never-called function whose entry point lives in the fixture image's
/// executable section.
///
/// The parent patches its existing bytes back through `Process::write_code`;
/// taking its address keeps it in the image.
#[inline(never)]
fn code_target() -> u64 {
    std::hint::black_box(0x5EED_1234_ABCD_0001_u64)
}

/// A Windows-only two-page allocation with different initial protections.
///
/// The address is exposed through `MULTI`. The allocation is intentionally kept
/// for the process lifetime and is never executed.
#[cfg(windows)]
struct MultiPageTarget {
    base: *mut std::ffi::c_void,
    len: usize,
    page_size: usize,
}

/// A Linux-only executable mapping of `/dev/zero`.
///
/// The mapping exists so the parent can prove that a device-backed "module" is
/// rejected before its file is read (reading `/dev/zero` would never finish).
#[cfg(target_os = "linux")]
fn zero_target() -> u64 {
    // SAFETY: `open` has no pointer preconditions; the returned descriptor is
    // checked and closed after `mmap` has duplicated the mapping.
    let fd = unsafe { libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open /dev/zero");
    // SAFETY: a null address lets the kernel choose a page-aligned range. The
    // resulting pointer is checked and owns `len` mapped bytes.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    };
    // SAFETY: the descriptor was opened above and is no longer needed.
    unsafe { libc::close(fd) };
    assert!(address != libc::MAP_FAILED, "mmap /dev/zero");
    address as usize as u64
}

#[cfg(windows)]
fn multi_page_target() -> MultiPageTarget {
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READONLY,
        PAGE_READWRITE, VirtualAlloc, VirtualProtect,
    };
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

    // SAFETY: SYSTEM_INFO is a plain-old-data Win32 struct; all-zero is a valid
    // initial value.
    let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: GetSystemInfo writes a SYSTEM_INFO to the provided pointer.
    unsafe { GetSystemInfo(&mut info) };
    let page_size = info.dwPageSize as usize;
    assert!(page_size > 0, "GetSystemInfo returned a zero page size");
    let len = page_size.checked_mul(2).expect("two pages fit in usize");

    // SAFETY: a null base asks the OS to choose a page-aligned range. The
    // returned pointer is checked for null and owns `len` writable bytes.
    let base = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    assert!(
        !base.is_null(),
        "VirtualAlloc failed for the multi-page target"
    );

    let bytes = pattern(len);
    // SAFETY: `base` is a valid writable allocation of `len` bytes and `bytes`
    // contains exactly `len` initialized bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.cast::<u8>(), len);
    }

    let mut previous: PAGE_PROTECTION_FLAGS = 0;
    // SAFETY: `base` is the first page of the writable allocation and
    // `previous` is writable for one value.
    let first = unsafe {
        VirtualProtect(
            base as *const std::ffi::c_void,
            page_size,
            PAGE_EXECUTE_READ,
            &mut previous,
        )
    };
    assert_ne!(first, 0, "VirtualProtect failed for the first page");

    let second_address = (base as usize)
        .checked_add(page_size)
        .expect("two-page allocation address fits in usize");
    // SAFETY: `second_address` is the second page of the allocation and
    // `previous` is writable for one value.
    let second = unsafe {
        VirtualProtect(
            second_address as *const std::ffi::c_void,
            page_size,
            PAGE_READONLY,
            &mut previous,
        )
    };
    assert_ne!(second, 0, "VirtualProtect failed for the second page");

    MultiPageTarget {
        base,
        len,
        page_size,
    }
}

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
    let code_address = code_target as *const () as usize;
    #[cfg(windows)]
    let multi_page = multi_page_target();
    #[cfg(target_os = "linux")]
    let zero_address = zero_target();
    #[cfg(target_os = "linux")]
    std::hint::black_box(zero_address);
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
            Some("CODE") => writeln!(output, "CODE {code_address} {CODE_LEN}")?,
            #[cfg(windows)]
            Some("MULTI") => writeln!(
                output,
                "MULTI {} {} {}",
                multi_page.base as usize, multi_page.len, multi_page.page_size
            )?,
            #[cfg(target_os = "linux")]
            Some("ZERO") => writeln!(output, "ZERO {zero_address}")?,
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
            #[cfg(target_os = "linux")]
            Some("EXEC") => {
                use std::ffi::CString;
                use std::os::unix::ffi::OsStrExt;

                let exe = std::env::current_exe().expect("current fixture executable");
                let path = CString::new(exe.as_os_str().as_bytes())
                    .expect("fixture path must not contain NUL");
                let argv = [path.as_ptr(), std::ptr::null()];
                // SAFETY: `path` is a valid NUL-terminated path and `argv` is a
                // NULL-terminated argument vector. On success this never returns.
                unsafe { libc::execv(path.as_ptr(), argv.as_ptr()) };
                writeln!(output, "ERR")?;
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

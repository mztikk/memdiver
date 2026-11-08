//! Linux backend built on `/proc/<pid>/mem` and `/proc/<pid>/maps`.
//!
//! A [`ProcessHandle`] pins three things for its lifetime:
//!
//! * the `/proc/<pid>` directory file descriptor,
//! * the `/proc/<pid>/mem` file descriptor, and
//! * the process start time from `/proc/<pid>/stat`.
//!
//! The memory file descriptor refers to the memory map that existed when it was
//! opened. The start time lets the handle detect PID reuse for the queries that
//! have to reopen procfs files (maps and stat). This is why the handle never
//! performs a read by PID alone.

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use crate::{Error, ErrorKind, Protection, RawModule, RawRegion, RegionKind, io_message};

const MEM: &CStr = c"mem";
const STAT: &CStr = c"stat";
const MAPS: &CStr = c"maps";

/// A pinned handle to a Linux process.
///
/// Created with [`ProcessHandle::open`]. Dropping the handle closes the procfs
/// descriptors but never terminates the target process.
pub struct ProcessHandle {
    pid: u32,
    proc_dir: File,
    mem: File,
    start_time: u64,
}

impl fmt::Debug for ProcessHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessHandle")
            .field("pid", &self.pid)
            .field("start_time", &self.start_time)
            .finish_non_exhaustive()
    }
}

impl ProcessHandle {
    /// Opens a handle to the process with the given PID.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::NotFound`] when the process does not exist,
    /// [`ErrorKind::PermissionDenied`] when the ptrace access check denies the
    /// caller, [`ErrorKind::ProcessExited`] when the process exits or its PID is
    /// reused during open, and [`ErrorKind::MalformedData`] when procfs data
    /// cannot be parsed.
    pub fn open(pid: u32) -> Result<Self, Error> {
        let proc_dir = File::open(format!("/proc/{pid}")).map_err(io_error)?;

        // Read the identity before and after opening the memory file. If the
        // PID is recycled during open, the start times differ and the handle is
        // rejected instead of combining one process's memory with another
        // process's metadata.
        let before = read_stat(&proc_dir, pid)?;
        let mem = open_proc_file(&proc_dir, MEM, libc::O_RDWR).map_err(io_error)?;
        let after = read_stat(&proc_dir, pid)?;
        if before.start_time != after.start_time || is_dead_state(after.state) {
            return Err(process_exited(pid));
        }

        Ok(Self {
            pid,
            proc_dir,
            mem,
            start_time: after.start_time,
        })
    }

    /// Returns the PID this handle was opened for.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Reads up to `buffer.len()` bytes starting at `address`.
    ///
    /// Returns the number of bytes transferred. A short transfer is not an
    /// error at this layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the address range cannot be represented as a
    /// procfs file offset or when the kernel rejects the read.
    pub fn read(&self, address: u64, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let offset = procfs_offset(address, buffer.len())?;
        pread(&self.mem, buffer, offset).map_err(io_error)
    }

    /// Writes up to `buffer.len()` bytes starting at `address`.
    ///
    /// Returns the number of bytes transferred. A short transfer is not an
    /// error at this layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the address range cannot be represented as a
    /// procfs file offset or when the kernel rejects the write.
    pub fn write(&self, address: u64, buffer: &[u8]) -> Result<usize, Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let offset = procfs_offset(address, buffer.len())?;
        pwrite(&self.mem, buffer, offset).map_err(io_error)
    }

    /// Returns whether the process is still running.
    ///
    /// A zombie or dead process is reported as not alive, as is a process whose
    /// PID has been reused since the handle was opened. Errors while reading
    /// procfs are treated as "not alive".
    #[must_use]
    pub fn is_alive(&self) -> bool {
        match self.current_stat() {
            Ok(stat) => stat.start_time == self.start_time && !is_dead_state(stat.state),
            Err(_) => false,
        }
    }

    /// Enumerates the committed memory regions of the process.
    ///
    /// # Errors
    ///
    /// Returns an error when the process exited, PID reuse is detected, or
    /// `/proc/<pid>/maps` cannot be read or parsed.
    pub fn regions(&self) -> Result<Vec<RawRegion>, Error> {
        self.ensure_same_process()?;
        let data = read_proc_file(&self.proc_dir, MAPS)?;
        let regions = parse_maps(&data, self.pid)?;
        // Check again after reading: a PID reused while `/proc/<pid>/maps` was
        // open would otherwise produce regions that belong to another process.
        self.ensure_same_process()?;
        Ok(regions)
    }

    /// Enumerates the executable modules loaded by the process.
    ///
    /// On Linux a module is a file-backed mapping with at least one executable
    /// segment. All mappings of that file are merged into one module whose base
    /// is the lowest mapping address.
    ///
    /// # Errors
    ///
    /// Returns an error when the process exited, PID reuse is detected, or
    /// `/proc/<pid>/maps` cannot be read or parsed.
    pub fn modules(&self) -> Result<Vec<RawModule>, Error> {
        let regions = self.regions()?;
        Ok(modules_from_regions(&regions))
    }

    /// Changes the protection of a memory range.
    ///
    /// Linux does not provide a way for one process to change another process's
    /// page protections. This method always returns
    /// [`ErrorKind::Unsupported`].
    ///
    /// # Errors
    ///
    /// Always returns [`ErrorKind::Unsupported`] on Linux.
    pub fn protect(
        &self,
        _address: u64,
        _len: usize,
        _protection: Protection,
    ) -> Result<Protection, Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            None,
            "changing another process's page protection is not supported on Linux",
        ))
    }

    fn current_stat(&self) -> Result<Stat, Error> {
        read_stat(&self.proc_dir, self.pid)
    }

    fn ensure_same_process(&self) -> Result<(), Error> {
        match self.current_stat() {
            Ok(stat) if stat.start_time == self.start_time && !is_dead_state(stat.state) => Ok(()),
            Ok(_) => Err(process_exited(self.pid)),
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::ProcessExited) =>
            {
                Err(process_exited(self.pid))
            }
            Err(error) => Err(error),
        }
    }
}

fn process_exited(pid: u32) -> Error {
    Error::new(
        ErrorKind::ProcessExited,
        None,
        format!("process {pid} exited or its PID was reused"),
    )
}

fn open_proc_file(dir: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: `dir` is an open directory descriptor, `name` is a valid
    // NUL-terminated path relative to it, and `flags` contains no O_CREAT or
    // other flag requiring a mode argument. The returned descriptor is owned
    // by the File constructed below.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` is a fresh, valid descriptor and ownership is
        // transferred exactly once to the returned File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn read_proc_file(dir: &File, name: &CStr) -> Result<Vec<u8>, Error> {
    let mut file = open_proc_file(dir, name, libc::O_RDONLY).map_err(io_error)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(io_error)?;
    Ok(data)
}

fn pread(file: &File, buffer: &mut [u8], offset: i64) -> io::Result<usize> {
    loop {
        // SAFETY: the descriptor is open, `buffer` is valid for writes of
        // `buffer.len()` bytes, and `offset` was checked to be non-negative.
        let result = unsafe {
            libc::pread64(
                file.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                offset,
            )
        };
        if result >= 0 {
            // A non-negative ssize_t is always representable as usize.
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn pwrite(file: &File, buffer: &[u8], offset: i64) -> io::Result<usize> {
    loop {
        // SAFETY: the descriptor is open, `buffer` is valid for reads of
        // `buffer.len()` bytes, and `offset` was checked to be non-negative.
        let result = unsafe {
            libc::pwrite64(
                file.as_raw_fd(),
                buffer.as_ptr().cast(),
                buffer.len(),
                offset,
            )
        };
        if result >= 0 {
            // A non-negative ssize_t is always representable as usize.
            return Ok(result as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn procfs_offset(address: u64, len: usize) -> Result<i64, Error> {
    let len = u64::try_from(len).map_err(|_| invalid_range(address))?;
    address
        .checked_add(len)
        .filter(|end| *end <= i64::MAX as u64)
        .ok_or_else(|| invalid_range(address))?;
    i64::try_from(address).map_err(|_| invalid_range(address))
}

fn invalid_range(address: u64) -> Error {
    Error::new(
        ErrorKind::InvalidAddress,
        None,
        format!("address range starting at {address:#x} cannot be represented by /proc/<pid>/mem"),
    )
}

fn io_error(error: io::Error) -> Error {
    let raw_code = error.raw_os_error();
    let kind = match raw_code {
        Some(libc::ENOENT) => ErrorKind::NotFound,
        Some(libc::ESRCH) => ErrorKind::ProcessExited,
        Some(libc::EACCES | libc::EPERM) => ErrorKind::PermissionDenied,
        Some(libc::EINVAL) => ErrorKind::InvalidAddress,
        Some(libc::ENOSYS) => ErrorKind::Unsupported,
        _ => ErrorKind::Other,
    };
    let message = raw_code.map_or_else(|| error.to_string(), io_message);
    Error::new(kind, raw_code, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stat {
    state: u8,
    start_time: u64,
}

fn read_stat(dir: &File, pid: u32) -> Result<Stat, Error> {
    let data = read_proc_file(dir, STAT)?;
    parse_stat(&data, pid)
}

fn parse_stat(data: &[u8], pid: u32) -> Result<Stat, Error> {
    let malformed =
        |reason: &str| Error::malformed(format!("/proc/{pid}/stat is malformed: {reason}"));

    let close = data
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(|| malformed("missing command terminator"))?;
    let tail = data
        .get(close + 1..)
        .ok_or_else(|| malformed("truncated"))?;
    let mut fields = tail
        .split(|byte: &u8| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let state = fields
        .next()
        .and_then(|field| field.first().copied())
        .ok_or_else(|| malformed("missing process state"))?;
    let start_time = fields
        .nth(18)
        .ok_or_else(|| malformed("missing start time"))?;
    let start_time = std::str::from_utf8(start_time)
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(|| malformed("invalid start time"))?;

    Ok(Stat { state, start_time })
}

fn is_dead_state(state: u8) -> bool {
    matches!(state, b'Z' | b'X' | b'x')
}

fn parse_maps(data: &[u8], pid: u32) -> Result<Vec<RawRegion>, Error> {
    let mut regions = Vec::new();
    for (index, line) in data.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let region = parse_maps_line(line).map_err(|reason| {
            Error::malformed(format!(
                "/proc/{pid}/maps line {} is malformed: {reason}",
                index + 1
            ))
        })?;
        regions.push(region);
    }
    regions.sort_by_key(|region| region.base);
    Ok(regions)
}

fn parse_maps_line(line: &[u8]) -> Result<RawRegion, String> {
    let mut position = 0;
    let range = next_field(line, &mut position).ok_or("missing address range")?;
    let permissions = next_field(line, &mut position).ok_or("missing permissions")?;
    next_field(line, &mut position).ok_or("missing file offset")?;
    next_field(line, &mut position).ok_or("missing device")?;
    next_field(line, &mut position).ok_or("missing inode")?;

    let (base, end) = parse_range(range)?;
    let protection = parse_permissions(permissions)?;

    let path = {
        // The kernel pads the pathname column with spaces after the inode.
        // Skip the whole padding run; real paths are absolute and start with
        // '/', and special mappings start with '['.
        while position < line.len() && line[position].is_ascii_whitespace() {
            position += 1;
        }
        let bytes = line.get(position..).unwrap_or_default();
        let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
        if bytes.is_empty() || bytes.first() == Some(&b'[') {
            None
        } else {
            Some(PathBuf::from(OsString::from_vec(bytes.to_vec())))
        }
    };
    let kind = if path.is_some() {
        RegionKind::Mapped
    } else {
        RegionKind::Private
    };

    Ok(RawRegion {
        base,
        size: end - base,
        protection,
        kind,
        path,
    })
}

fn next_field<'a>(line: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    while *position < line.len() && line[*position] == b' ' {
        *position += 1;
    }
    if *position >= line.len() {
        return None;
    }
    let start = *position;
    while *position < line.len() && line[*position] != b' ' {
        *position += 1;
    }
    Some(&line[start..*position])
}

fn parse_range(token: &[u8]) -> Result<(u64, u64), String> {
    let dash = token
        .iter()
        .position(|byte| *byte == b'-')
        .ok_or("address range lacks '-'")?;
    let (start, rest) = token.split_at(dash);
    let end = rest.get(1..).ok_or("address range lacks end")?;
    let start = parse_hex(start)?;
    let end = parse_hex(end)?;
    if end <= start {
        return Err("address range end is not greater than its start".to_owned());
    }
    Ok((start, end))
}

fn parse_hex(bytes: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "address is not ASCII")?;
    u64::from_str_radix(text, 16).map_err(|_| format!("invalid hexadecimal number {text:?}"))
}

fn parse_permissions(permissions: &[u8]) -> Result<Protection, String> {
    if permissions.len() != 4 {
        return Err("permissions must contain four characters".to_owned());
    }
    if !matches!(permissions[3], b'p' | b's') {
        return Err("mapping must be private or shared".to_owned());
    }
    Ok(permission(permissions[0], b'r', Protection::READ)?
        | permission(permissions[1], b'w', Protection::WRITE)?
        | permission(permissions[2], b'x', Protection::EXECUTE)?)
}

fn permission(actual: u8, expected: u8, flag: Protection) -> Result<Protection, String> {
    match actual {
        byte if byte == expected => Ok(flag),
        b'-' => Ok(Protection::empty()),
        other => Err(format!("invalid permission byte {:?}", char::from(other))),
    }
}

fn modules_from_regions(regions: &[RawRegion]) -> Vec<RawModule> {
    let executable_paths: HashSet<&Path> = regions
        .iter()
        .filter(|region| region.protection.is_executable())
        .filter_map(|region| region.path.as_deref())
        .collect();

    let mut spans: HashMap<&Path, (u64, u64)> = HashMap::new();
    for region in regions {
        let Some(path) = region.path.as_deref() else {
            continue;
        };
        if !executable_paths.contains(path) {
            continue;
        }
        let end = region.base.saturating_add(region.size);
        let span = spans.entry(path).or_insert((region.base, end));
        span.0 = span.0.min(region.base);
        span.1 = span.1.max(end);
    }

    let mut modules: Vec<RawModule> = spans
        .into_iter()
        .filter_map(|(path, (base, end))| {
            let size = end.checked_sub(base)?;
            if size == 0 {
                return None;
            }
            let name = path.file_name().map_or_else(
                || path.to_string_lossy().into_owned(),
                |name| name.to_string_lossy().into_owned(),
            );
            Some(RawModule {
                name,
                path: path.to_path_buf(),
                base,
                size,
            })
        })
        .collect();
    modules.sort_by(|left, right| {
        left.base
            .cmp(&right.base)
            .then_with(|| left.name.cmp(&right.name))
    });
    modules
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_line(state: u8, start_time: u64) -> Vec<u8> {
        let mut line = format!("4242 (memdiver fixture) {}", char::from(state));
        for field in 4..22 {
            line.push(' ');
            line.push_str(&field.to_string());
        }
        line.push(' ');
        line.push_str(&start_time.to_string());
        line.into_bytes()
    }

    #[test]
    fn parses_stat_and_start_time() {
        let stat = parse_stat(&stat_line(b'S', 987_654), 4242).expect("valid stat");
        assert_eq!(stat.state, b'S');
        assert_eq!(stat.start_time, 987_654);
    }

    #[test]
    fn parses_stat_with_comm_containing_spaces_and_parentheses() {
        let mut line = b"77 (a) tricky ) process) R".to_vec();
        for field in 4..=21 {
            line.push(b' ');
            line.extend_from_slice(field.to_string().as_bytes());
        }
        line.extend_from_slice(b" 1234");
        let stat = parse_stat(&line, 77).expect("valid stat");
        assert_eq!(stat.state, b'R');
        assert_eq!(stat.start_time, 1234);
    }

    #[test]
    fn parses_zombie_state() {
        let stat = parse_stat(&stat_line(b'Z', 1), 4242).expect("valid stat");
        assert!(is_dead_state(stat.state));
        assert!(!is_dead_state(b'S'));
        assert!(!is_dead_state(b'R'));
    }

    #[test]
    fn rejects_malformed_stat() {
        assert_eq!(
            parse_stat(b"42 no closing parenthesis", 42)
                .expect_err("must fail")
                .kind(),
            ErrorKind::MalformedData
        );
        assert_eq!(
            parse_stat(b"42 (comm) S 1 2", 42)
                .expect_err("must fail")
                .kind(),
            ErrorKind::MalformedData
        );

        let mut line = stat_line(b'S', 1);
        let last_space = line.iter().rposition(|byte| *byte == b' ').expect("space");
        line.truncate(last_space);
        line.extend_from_slice(b" not-a-number");
        assert_eq!(
            parse_stat(&line, 42).expect_err("must fail").kind(),
            ErrorKind::MalformedData
        );
    }

    fn maps_line(prefix: &str, path: &str) -> Vec<u8> {
        format!("{prefix} {path}").into_bytes()
    }

    #[test]
    fn parses_regular_maps_entry() {
        let line = b"7f0000000000-7f0000001000 r-xp 00000000 08:01 1234 /usr/lib/libfoo.so.1";
        let region = parse_maps_line(line).expect("valid maps line");
        assert_eq!(region.base, 0x7f00_0000_0000);
        assert_eq!(region.size, 0x1000);
        assert_eq!(region.protection, Protection::READ | Protection::EXECUTE);
        assert_eq!(region.kind, RegionKind::Mapped);
        assert_eq!(
            region.path.as_deref(),
            Some(Path::new("/usr/lib/libfoo.so.1"))
        );
    }

    #[test]
    fn parses_shared_and_write_only_permissions() {
        let shared = parse_maps_line(b"1000-2000 rw-s 00000000 00:00 0 /tmp/shared")
            .expect("valid maps line");
        assert_eq!(shared.protection, Protection::READ | Protection::WRITE);

        let write_only =
            parse_maps_line(b"2000-3000 -w-p 00000000 00:00 0").expect("valid maps line");
        assert_eq!(write_only.protection, Protection::WRITE);
        assert_eq!(write_only.path, None);
        assert_eq!(write_only.kind, RegionKind::Private);
    }

    #[test]
    fn parses_paths_with_spaces_and_deleted_suffix() {
        let line = maps_line(
            "1000-2000 rw-p 00000000 00:00 7",
            "/tmp/name with spaces (deleted)",
        );
        let region = parse_maps_line(&line).expect("valid maps line");
        assert_eq!(
            region.path.as_deref(),
            Some(Path::new("/tmp/name with spaces"))
        );
    }

    #[test]
    fn parses_pathname_column_padding() {
        let line = b"1000-2000 r-xp 00000000 00:00 1234                    /usr/lib/libfoo.so.1";
        let region = parse_maps_line(line).expect("valid padded maps line");
        assert_eq!(
            region.path.as_deref(),
            Some(Path::new("/usr/lib/libfoo.so.1"))
        );

        let heap =
            parse_maps_line(b"2000-3000 rw-p 00000000 00:00 0                          [heap]")
                .expect("valid padded heap line");
        assert_eq!(heap.path, None);
        assert_eq!(heap.kind, RegionKind::Private);
    }

    #[test]
    fn preserves_non_utf8_mapping_paths() {
        use std::os::unix::ffi::OsStrExt;

        let line = b"1000-2000 r-xp 00000000 00:00 9 /tmp/name-\xff";
        let region = parse_maps_line(line).expect("valid maps line");
        let path = region.path.expect("file-backed mapping has a path");
        assert_eq!(path.as_os_str().as_bytes(), b"/tmp/name-\xff");
    }

    #[test]
    fn special_mappings_have_no_path() {
        let heap =
            parse_maps_line(b"5555-6666 rw-p 00000000 00:00 0 [heap]").expect("valid maps line");
        assert_eq!(heap.path, None);
        assert_eq!(heap.kind, RegionKind::Private);
    }

    #[test]
    fn rejects_malformed_maps_lines() {
        let invalid = [
            b"1000-2000".as_slice(),
            b"1000-2000 r-xp".as_slice(),
            b"zzzz-2000 r-xp 0 0 0".as_slice(),
            b"1000-1000 r-xp 0 0 0".as_slice(),
            b"1000-2000 r-xq 0 0 0".as_slice(),
            b"1000-2000 r-x 0 0 0".as_slice(),
            b"1000-2000 r-xp 0 0".as_slice(),
        ];
        for line in invalid {
            assert!(
                parse_maps_line(line).is_err(),
                "line {:?} should be rejected",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn parse_maps_sorts_and_numbers_lines() {
        let data = b"2000-3000 rw-p 0 0 0 [heap]\n1000-2000 r-xp 0 0 0 /bin/app\n";
        let regions = parse_maps(data, 7).expect("valid maps");
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].base, 0x1000);
        assert_eq!(regions[1].base, 0x2000);

        let error = parse_maps(b"1000-2000 rw-p 0 0 0\nbad\n", 7).expect_err("must fail");
        assert_eq!(error.kind(), ErrorKind::MalformedData);
        assert!(error.message().contains("line 2"));
    }

    fn raw_region(base: u64, size: u64, protection: Protection, path: Option<&str>) -> RawRegion {
        RawRegion {
            base,
            size,
            protection,
            kind: if path.is_some() {
                RegionKind::Mapped
            } else {
                RegionKind::Private
            },
            path: path.map(PathBuf::from),
        }
    }

    #[test]
    fn modules_merge_executable_mappings_only() {
        let regions = vec![
            raw_region(0x1000, 0x1000, Protection::READ, Some("/lib/libx.so.1")),
            raw_region(
                0x2000,
                0x1000,
                Protection::READ | Protection::EXECUTE,
                Some("/lib/libx.so.1"),
            ),
            raw_region(0x3000, 0x1000, Protection::READ, Some("/data/file")),
            raw_region(0x4000, 0x1000, Protection::READ | Protection::WRITE, None),
            raw_region(
                0x5000,
                0x1000,
                Protection::READ | Protection::EXECUTE,
                Some("/usr/bin/app"),
            ),
        ];
        let modules = modules_from_regions(&regions);
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name, "libx.so.1");
        assert_eq!(modules[0].base, 0x1000);
        assert_eq!(modules[0].size, 0x2000);
        assert_eq!(modules[1].name, "app");
        assert_eq!(modules[1].base, 0x5000);
        assert_eq!(modules[1].size, 0x1000);
    }

    #[test]
    fn modules_ignore_anonymous_executable_mappings() {
        let regions = vec![raw_region(
            0x1000,
            0x1000,
            Protection::READ | Protection::EXECUTE,
            None,
        )];
        assert!(modules_from_regions(&regions).is_empty());
    }

    #[test]
    fn rejects_procfs_offsets_beyond_i64() {
        assert!(procfs_offset(i64::MAX as u64, 1).is_err());
        assert!(procfs_offset(0, 16).is_ok());
        assert_eq!(
            procfs_offset(u64::MAX, 1).expect_err("must fail").kind(),
            ErrorKind::InvalidAddress
        );
    }

    #[test]
    fn classifies_io_errors() {
        assert_eq!(
            io_error(io::Error::from_raw_os_error(libc::ENOENT)).kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            io_error(io::Error::from_raw_os_error(libc::EACCES)).kind(),
            ErrorKind::PermissionDenied
        );
        assert_eq!(
            io_error(io::Error::from_raw_os_error(libc::ESRCH)).kind(),
            ErrorKind::ProcessExited
        );
        assert_eq!(
            io_error(io::Error::from_raw_os_error(libc::EINVAL)).kind(),
            ErrorKind::InvalidAddress
        );
    }
}

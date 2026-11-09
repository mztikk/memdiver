//! Shared harness for the end-to-end tests.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use memdiver::{Address, Process};

/// Upper bound for the fixture handshake and every command response.
const FIXTURE_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Number of bytes in the fixture's buffer.
pub const BUFFER_LEN: usize = 4096;
/// Multiplier used by the deterministic fixture pattern.
pub const MULTIPLIER: u8 = 37;
/// Addend used by the deterministic fixture pattern.
pub const ADDEND: u8 = 11;
/// Signature embedded in the fixture executable's read-only data.
pub const MODULE_SIGNATURE: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0x6D, 0x65, 0x6D, 0x64, 0x69, 0x76, 0x65, 0x72, 0x21, 0x7F, 0x3C, 0x9A,
];

/// Number of executable bytes returned by the fixture's `CODE` command.
///
/// Keep this in sync with `CODE_LEN` in `memdiver-fixture.rs`.
pub const CODE_LEN: usize = 4;

/// A Windows-only two-page fixture allocation with different protections.
///
/// The first page is executable and read-only; the second is read-only. The
/// fixture never executes this memory.
#[cfg(windows)]
pub struct MultiPageTarget {
    /// First address of the allocation.
    pub address: Address,
    /// Total length of the two-page allocation.
    pub len: usize,
    /// System page size reported by the fixture.
    pub page_size: usize,
}

/// Returns `MODULE_SIGNATURE` formatted as a scanning pattern.
pub fn module_signature_text() -> String {
    MODULE_SIGNATURE
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Returns the deterministic byte pattern used by the fixture.
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(MULTIPLIER).wrapping_add(ADDEND))
        .collect()
}

/// Returns the path of the compiled fixture binary.
pub fn fixture_exe() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_memdiver-fixture"))
}

/// Returns the file name of the compiled fixture binary.
pub fn fixture_name() -> String {
    fixture_exe()
        .file_name()
        .expect("fixture binary has a file name")
        .to_string_lossy()
        .into_owned()
}

/// Compares module names using the platform's filename semantics.
pub fn names_equal(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        left.eq_ignore_ascii_case(right)
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

/// A running fixture process plus an open [`Process`] handle to it.
pub struct Fixture {
    /// Open handle to the child.
    pub process: Process,
    /// Address of the fixture's buffer.
    pub address: Address,
    /// Length of the fixture's buffer.
    pub len: usize,
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    reader: Option<JoinHandle<()>>,
    exe_path: Option<std::path::PathBuf>,
}

impl Fixture {
    /// Starts a fixture and opens it through the public API.
    pub fn spawn() -> Self {
        Self::spawn_from(fixture_exe(), None)
    }

    /// Starts a fixture from a uniquely named copy of the fixture binary.
    ///
    /// A test process can have several copies of itself with the same image
    /// name (libtest may run tests in child processes), so opening "the current
    /// test binary by name" is not deterministic. A uniquely named copy makes
    /// the name-open path deterministic; the copy is removed on drop.
    pub fn spawn_unique() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("memdiver-fixture-{}-{serial}", std::process::id());
        let path = fixture_exe().with_file_name(&name);
        std::fs::copy(fixture_exe(), &path).expect("copy fixture binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&path)
                .expect("fixture copy metadata")
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).expect("make fixture copy executable");
        }
        // Remove the copy if the handshake panics before a Fixture owns it.
        let mut cleanup = RemoveOnDrop(Some(path.clone()));
        let fixture = Self::spawn_from(&path, Some(path.clone()));
        cleanup.0 = None;
        fixture
    }

    /// Returns the executable name the fixture was started from.
    pub fn name(&self) -> String {
        self.exe_path
            .as_deref()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(fixture_name)
    }

    fn spawn_from(exe: &Path, cleanup: Option<std::path::PathBuf>) -> Self {
        let mut child = Command::new(exe)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn memdiver-fixture");
        let stdin = child.stdin.take().expect("fixture stdin");
        let stdout = child.stdout.take().expect("fixture stdout");
        let (lines, reader) = read_lines(stdout);

        let ready = match lines.recv_timeout(FIXTURE_IO_TIMEOUT) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => abort_child(
                &mut child,
                reader,
                "fixture did not print READY within the handshake timeout".to_owned(),
            ),
            Err(RecvTimeoutError::Disconnected) => abort_child(
                &mut child,
                reader,
                "fixture exited before printing READY".to_owned(),
            ),
        };

        let fields: Vec<&str> = ready.split_whitespace().collect();
        if fields.len() != 4 || fields[0] != "READY" {
            abort_child(
                &mut child,
                reader,
                format!("unexpected READY line: {ready:?}"),
            );
        }
        let pid: u32 = match fields[1].parse() {
            Ok(pid) => pid,
            Err(_) => abort_child(
                &mut child,
                reader,
                format!("invalid fixture pid in {ready:?}"),
            ),
        };
        let address: u64 = match fields[2].parse() {
            Ok(address) => address,
            Err(_) => abort_child(
                &mut child,
                reader,
                format!("invalid fixture address in {ready:?}"),
            ),
        };
        let len: usize = match fields[3].parse() {
            Ok(len) => len,
            Err(_) => abort_child(
                &mut child,
                reader,
                format!("invalid fixture length in {ready:?}"),
            ),
        };
        if pid != child.id() || len != BUFFER_LEN {
            abort_child(
                &mut child,
                reader,
                format!("fixture reported inconsistent identity or length: {ready:?}"),
            );
        }

        let process = match Process::open(pid) {
            Ok(process) => process,
            Err(error) => abort_child(
                &mut child,
                reader,
                format!("could not open fixture process {pid}: {error}"),
            ),
        };

        Self {
            process,
            address: Address::new(address),
            len,
            child,
            stdin,
            lines,
            reader: Some(reader),
            exe_path: cleanup,
        }
    }

    /// Returns the full current contents of the fixture buffer.
    pub fn peek_all(&mut self) -> Vec<u8> {
        self.peek(0, self.len)
    }

    /// Returns a range of the fixture buffer as observed by the fixture.
    pub fn peek(&mut self, offset: usize, len: usize) -> Vec<u8> {
        self.request(&format!("PEEK {offset} {len}"));
        let response = self.response();
        assert_ne!(response, "ERR", "fixture rejected PEEK {offset} {len}");
        decode_hex(&response)
    }

    /// Checks that the fixture is responsive.
    pub fn ping(&mut self) {
        self.request("PING");
        assert_eq!(self.response(), "PONG");
    }

    /// Returns the address and length of the fixture's executable code target.
    ///
    /// The bytes at this address are already what the parent is expected to
    /// write back, so a failed protection restore does not alter the fixture's
    /// behaviour.
    pub fn code_target(&mut self) -> (Address, usize) {
        self.request("CODE");
        let response = self.response();
        let fields: Vec<&str> = response.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "unexpected CODE response: {response:?}");
        assert_eq!(fields[0], "CODE");
        let address: u64 = fields[1].parse().expect("code target address");
        let len: usize = fields[2].parse().expect("code target length");
        assert_eq!(len, CODE_LEN);
        (Address::new(address), len)
    }

    /// Returns the Windows-only two-page allocation with differing protections.
    ///
    /// The first page is executable and read-only; the second is read-only. The
    /// fixture keeps the allocation alive and never executes it.
    #[cfg(windows)]
    pub fn multi_page_target(&mut self) -> MultiPageTarget {
        self.request("MULTI");
        let response = self.response();
        let fields: Vec<&str> = response.split_whitespace().collect();
        assert_eq!(fields.len(), 4, "unexpected MULTI response: {response:?}");
        assert_eq!(fields[0], "MULTI");
        let address: u64 = fields[1].parse().expect("multi-page address");
        let len: usize = fields[2].parse().expect("multi-page length");
        let page_size: usize = fields[3].parse().expect("multi-page page size");
        assert!(page_size > 0, "fixture reported a zero page size");
        assert_eq!(
            len,
            page_size.checked_mul(2).expect("two pages fit in usize"),
            "multi-page target must span exactly two pages"
        );
        MultiPageTarget {
            address: Address::new(address),
            len,
            page_size,
        }
    }

    /// Returns the address of the fixture's executable `/dev/zero` mapping.
    ///
    /// Reading `/dev/zero` never reaches EOF, so this target proves that the
    /// module-file reader rejects device files before reading them.
    #[cfg(target_os = "linux")]
    pub fn zero_target(&mut self) -> Address {
        self.request("ZERO");
        let response = self.response();
        let fields: Vec<&str> = response.split_whitespace().collect();
        assert_eq!(fields.len(), 2, "unexpected ZERO response: {response:?}");
        assert_eq!(fields[0], "ZERO");
        Address::new(fields[1].parse().expect("zero target address"))
    }

    /// Returns the address and page size of the short-transfer target.
    ///
    /// The first page is readable and the next page is inaccessible, so a read
    /// that crosses the boundary transfers only the readable prefix.
    pub fn boundary_target(&mut self) -> (Address, usize) {
        self.page_pair_target("BOUNDARY")
    }

    /// Returns the address and page size of two adjacent readable pages with
    /// different protections.
    pub fn adjacent_target(&mut self) -> (Address, usize) {
        self.page_pair_target("ADJACENT")
    }

    fn page_pair_target(&mut self, command: &str) -> (Address, usize) {
        self.request(command);
        let response = self.response();
        let fields: Vec<&str> = response.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            3,
            "unexpected {command} response: {response:?}"
        );
        assert_eq!(fields[0], command);
        let address: u64 = fields[1].parse().expect("target address");
        let page_size: usize = fields[2].parse().expect("target page size");
        assert!(page_size > 0, "fixture reported a zero page size");
        (Address::new(address), page_size)
    }

    /// Asks the fixture to exit without reaping it.
    ///
    /// This lets a test observe a zombie on Linux and a signaled process on
    /// Windows; `Drop` still reaps the child.
    pub fn exit(&mut self) {
        self.request("EXIT");
    }

    /// Replaces the fixture image with itself.
    ///
    /// This keeps the PID and start time but installs a new address space, so
    /// a handle opened before the call must report `AddressSpaceReplaced`. The
    /// new image prints a fresh `READY` line, which is consumed and used to
    /// refresh the buffer address and length.
    #[cfg(target_os = "linux")]
    pub fn exec(&mut self) {
        self.request("EXEC");
        let ready = self.response();
        let fields: Vec<&str> = ready.split_whitespace().collect();
        assert_eq!(fields.len(), 4, "unexpected READY line: {ready:?}");
        assert_eq!(fields[0], "READY");
        let pid: u32 = fields[1].parse().expect("fixture pid");
        let address: u64 = fields[2].parse().expect("fixture address");
        let len: usize = fields[3].parse().expect("fixture length");
        assert_eq!(pid, self.child.id(), "the re-exec must keep the PID");
        assert_eq!(len, BUFFER_LEN, "unexpected re-exec buffer length");
        self.address = Address::new(address);
        self.len = len;
    }

    /// Kills and reaps the fixture process.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn request(&mut self, command: &str) {
        writeln!(self.stdin, "{command}").expect("write fixture command");
        self.stdin.flush().expect("flush fixture command");
    }

    fn response(&mut self) -> String {
        match self.lines.recv_timeout(FIXTURE_IO_TIMEOUT) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => {
                panic!("fixture did not respond within {FIXTURE_IO_TIMEOUT:?}")
            }
            Err(RecvTimeoutError::Disconnected) => panic!("fixture closed stdout"),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.kill();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(path) = self.exe_path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Removes a temporary fixture copy if construction unwinds.
struct RemoveOnDrop(Option<PathBuf>);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn read_lines(stdout: ChildStdout) -> (Receiver<String>, JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if sender.send(line.trim_end().to_owned()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    (receiver, reader)
}

fn abort_child(child: &mut Child, reader: JoinHandle<()>, message: String) -> ! {
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    panic!("{message}");
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert!(
        encoded.len() % 2 == 0,
        "odd-length hex response {encoded:?}"
    );
    (0..encoded.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&encoded[index..index + 2], 16)
                .expect("fixture returned valid hexadecimal")
        })
        .collect()
}

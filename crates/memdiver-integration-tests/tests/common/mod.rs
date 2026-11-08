//! Shared harness for the end-to-end tests.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use memdiver::{Address, Process};

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
    stdout: BufReader<ChildStdout>,
}

impl Fixture {
    /// Starts a fixture and opens it through the public API.
    pub fn spawn() -> Self {
        let mut child = Command::new(fixture_exe())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn memdiver-fixture");
        let stdin = child.stdin.take().expect("fixture stdin");
        let mut stdout = BufReader::new(child.stdout.take().expect("fixture stdout"));

        let mut ready = String::new();
        let read = stdout
            .read_line(&mut ready)
            .expect("read fixture READY line");
        if read == 0 {
            let _ = child.kill();
            let _ = child.wait();
            panic!("fixture exited before printing READY");
        }

        let fields: Vec<&str> = ready.split_whitespace().collect();
        assert_eq!(fields.len(), 4, "unexpected READY line: {ready:?}");
        assert_eq!(fields[0], "READY");
        let pid: u32 = fields[1].parse().expect("fixture pid");
        let address: u64 = fields[2].parse().expect("fixture buffer address");
        let len: usize = fields[3].parse().expect("fixture buffer length");
        assert_eq!(pid, child.id(), "fixture reported a different PID");
        assert_eq!(len, BUFFER_LEN);

        let process = match Process::open(pid) {
            Ok(process) => process,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("could not open fixture process {pid}: {error}");
            }
        };

        Self {
            process,
            address: Address::new(address),
            len,
            child,
            stdin,
            stdout,
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
        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .expect("read fixture response");
        assert_ne!(read, 0, "fixture closed stdout");
        line.trim_end().to_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.kill();
    }
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

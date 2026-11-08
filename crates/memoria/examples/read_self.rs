//! Reads a local value back through the external-memory API.
//!
//! This exercises the same code path used for another process without needing
//! two cooperating processes.
//!
//! ```sh
//! cargo run -p memoria --example read_self
//! ```

use memoria::{Address, Process};

fn main() -> Result<(), memoria::Error> {
    let value = std::hint::black_box(0xDEAD_BEEF_CAFE_F00D_u64);
    let process = Process::open(std::process::id())?;
    let address = Address::new((&value as *const u64) as u64);

    let observed: u64 = process.read_value(address)?;
    assert_eq!(observed, value);
    println!("read {observed:#018x} from our own process at {address}");

    Ok(())
}

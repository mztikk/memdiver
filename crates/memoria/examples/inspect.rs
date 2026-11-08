//! Inspect the memory map and loaded modules of a process.
//!
//! With no argument the example inspects itself. Pass a PID to inspect another
//! process you have permission to access.
//!
//! ```sh
//! cargo run -p memoria --example inspect
//! cargo run -p memoria --example inspect -- 1234
//! ```

use std::error::Error;

use memoria::Process;

fn main() -> Result<(), Box<dyn Error>> {
    let pid = match std::env::args().nth(1) {
        Some(raw) => raw.parse::<u32>()?,
        None => std::process::id(),
    };

    let process = Process::open(pid)?;
    println!("process {pid} (alive: {})", process.is_alive());

    let regions = process.regions()?;
    println!("\n{} committed regions:", regions.len());
    for region in &regions {
        let path = region.path().map_or_else(
            || "<anonymous>".to_owned(),
            |path| path.display().to_string(),
        );
        println!(
            "  {:#018x}..{:#018x} {:>10} bytes {:<12} {}",
            region.base().get(),
            region.end().get(),
            region.size(),
            region.protection().to_string(),
            path
        );
    }

    let modules = process.modules()?;
    println!("\n{} modules:", modules.len());
    for module in &modules {
        println!(
            "  {:#018x} {:>10} bytes  {}",
            module.base().get(),
            module.size(),
            module.path().display()
        );
    }

    if let Some(region) = regions.iter().find(|region| region.is_readable()) {
        match process.read_bytes(region.base(), 16) {
            Ok(bytes) => println!("\nfirst 16 bytes at {}: {:02x?}", region.base(), bytes),
            Err(error) => println!("\ncould not read {}: {error}", region.base()),
        }
    }

    Ok(())
}

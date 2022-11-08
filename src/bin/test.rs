use clap::{App, Arg, SubCommand};
use lpus::{driver_state::DriverState, scan_eprocess};
use std::error::Error;

#[macro_use]
extern crate prettytable;
use prettytable::{Cell, Row, Table};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!(
            "Windows version {:?} is not supported",
            driver.windows_ffi.short_version
        )
            .into());
    }
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());
    let pml4e_content: u64 = driver.deref_physical_addr(0x1234);
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

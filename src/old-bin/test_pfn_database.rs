use clap::{App, Arg, SubCommand};
use lpus::{driver_state::DriverState, scan_eprocess};
use std::error::Error;

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
    let ntosbase = driver.get_kernel_base();
    let pfn_database = ntosbase + driver.pdb_store.get_offset_r("MmPfnDatabase")?;
    println!("Addr of pfn_database: 0x{:x}", pfn_database.address());
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());

    Ok(())
}
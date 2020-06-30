use std::error::Error;

use lpus::{
    driver_state::{DriverState},
    scan_ethread, /* scan_mutant */
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!("Windows version {:?} is not supported", driver.windows_ffi.short_version).into());
    }
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    let threads = scan_ethread(&driver).unwrap_or(Vec::new());
    // let mutants = scan_mutant(&driver).unwrap_or(Vec::new());

    for r in threads.iter() {
        println!("{:#}", r.to_string());
    }
    // for r in mutants.iter() {
    //     println!("{:#}", r.to_string());
    // }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}



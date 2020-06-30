use std::error::Error;

use lpus::{
    driver_state::{DriverState},
    traverse_activehead,
    traverse_kiprocesslist,
    traverse_handletable
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!("Windows version {:?} is not supported", driver.windows_ffi.short_version).into());
    }
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    let activehead = traverse_activehead(&driver).unwrap_or(Vec::new());
    let kiprocesslist = traverse_kiprocesslist(&driver).unwrap_or(Vec::new());
    let handletable = traverse_handletable(&driver).unwrap_or(Vec::new());

    for r in activehead.iter() {
        println!("{:#}", r.to_string());
    }
    println!("=========================================");
    for r in kiprocesslist.iter() {
        println!("{:#}", r.to_string());
    }
    println!("=========================================");
    for r in handletable.iter() {
        println!("{:#}", r.to_string());
    }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}


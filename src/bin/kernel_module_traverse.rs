use std::error::Error;

use lpus::{
    driver_state::{DriverState},
    traverse_loadedmodulelist,
    traverse_unloadeddrivers
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    let loaded = traverse_loadedmodulelist(&driver).unwrap_or(Vec::new());
    let unloaded = traverse_unloadeddrivers(&driver).unwrap_or(Vec::new());

    for r in loaded.iter() {
        println!("{:#}", r.to_string());
    }
    println!("=============================================");
    for r in unloaded.iter() {
        println!("{:#}", r.to_string());
    }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

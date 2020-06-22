use std::error::Error;

use lpus::{
    driver_state::{DriverState},
    scan_driver
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    let result = scan_driver(&driver).unwrap_or(Vec::new());

    for r in result.iter() {
        println!("{:#}", r.to_string());
    }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

use std::error::Error;

use lpus::driver_state::DriverState;

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

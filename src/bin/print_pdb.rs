use std::error::Error;

use lpus::{
    driver_state::{DriverState},
};

fn main() -> Result<(), Box<dyn Error>> {
    let driver = DriverState::new();
    driver.windows_ffi.print_version();
    driver.pdb_store.print_default_information();
    Ok(())
}

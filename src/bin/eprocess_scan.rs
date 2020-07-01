use std::error::Error;

use lpus::{
    driver_state::DriverState, scan_eprocess, traverse_activehead, traverse_handletable,
    traverse_kiprocesslist,
};

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

    let scan = scan_eprocess(&driver).unwrap_or(Vec::new());
    let activehead = traverse_activehead(&driver).unwrap_or(Vec::new());
    let kiprocesslist = traverse_kiprocesslist(&driver).unwrap_or(Vec::new());
    let handletable = traverse_handletable(&driver).unwrap_or(Vec::new());

    for r in scan.iter() {
        println!("{:#}", r.to_string());
    }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

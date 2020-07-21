use serde_json::{json};
use std::error::Error;
use std::fs;


use lpus::{
    driver_state::DriverState, scan_eprocess, scan_ethread, traverse_activehead,
    traverse_handletable, traverse_kiprocesslist, scan_driver, scan_kernel_module,
    traverse_loadedmodulelist, traverse_unloadeddrivers,
    ssdt_table
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

    let eprocess_1 = scan_eprocess(&driver)?;
    let eprocess_2 = traverse_activehead(&driver)?;
    let eprocess_3 = traverse_kiprocesslist(&driver)?;
    let eprocess_4 = traverse_handletable(&driver)?;
    let ethread = scan_ethread(&driver)?;
    let drivers = scan_driver(&driver)?;
    let kernel_module_1 = scan_kernel_module(&driver)?;
    let kernel_module_2 = traverse_loadedmodulelist(&driver)?;
    let unloaded_driver = traverse_unloadeddrivers(&driver)?;
    let ssdt: Vec<String> = ssdt_table(&driver)?.into_iter().map(|x| format!("0x{:x}", x)).collect();

    let result = json!({
        "scan_eprocess": eprocess_1,
        "traverse_activehead": eprocess_2,
        "traverse_kiprocesslist": eprocess_3,
        "traverse_handletable": eprocess_4,
        "scan_ethread": ethread,
        "scan_driver": drivers,
        "scan_kernel_module": kernel_module_1,
        "traverse_loadedmodulelist": kernel_module_2,
        "traverse_unloadeddrivers": unloaded_driver,
        "ssdt_table": ssdt
    });

    fs::write("./lpus.json", format!("{:#}", result)).ok();

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

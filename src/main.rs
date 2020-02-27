mod pdb_store;
mod windows;
mod ioctl_protocol;
mod driver_state;

use pdb_store::parse_pdb;
use windows::WindowsFFI;
use driver_state::{DriverState, DriverAction};

fn main() {
    // for windows admin require
    // https://github.com/nabijaczleweli/rust-embed-resource

    let mut driver = DriverState::new(parse_pdb(), WindowsFFI::new());

    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    driver.interact(DriverAction::SetupOffset);
    driver.interact(DriverAction::GetKernelBase);
    driver.interact(DriverAction::ScanPsActiveHead);
    driver.interact(DriverAction::ScanPoolRemote);

    println!("PsActiveProcessHead traversal");
    println!("- [is in scan list?] eprocess_addr eprocess_name");
    for result in &driver.eprocess_traverse_result {
        println!("- [{}] 0x{:x} {}",
                 driver.pool_scan_result.contains(&result),
                 result.eprocess_addr, result.eprocess_name.trim_end_matches(char::from(0)));
    }

    println!("Pool tag (quick) scanning");
    println!("- [is in pslist?] pool_addr eprocess_addr eprocess_name");
    for result in &driver.pool_scan_result {
        println!("- [{}] 0x{:x} 0x{:x} {}",
                 driver.eprocess_traverse_result.contains(&result),
                 result.pool_addr, result.eprocess_addr, result.eprocess_name.trim_end_matches(char::from(0)));
    }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
}

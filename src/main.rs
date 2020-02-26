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
    // driver.interact(DriverAction::ScanPsActiveHead);
    // driver.interact(DriverAction::ScanPool);
    driver.interact(DriverAction::ScanPoolRemote);

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
}

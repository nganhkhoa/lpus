use std::error::Error;
// use std::time::{SystemTime, UNIX_EPOCH};

use lpus::{
    driver_state::{DriverState},
};

pub fn to_epoch(filetime: u64) -> u64 {
    // https://www.frenk.com/2009/12/convert-filetime-to-unix-timestamp/
    let windows_epoch_diff = 11644473600000 * 10000;
    if filetime < windows_epoch_diff {
        return 0;
    }
    let process_time_epoch = (filetime - windows_epoch_diff) / 10000;
    // let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64;

    process_time_epoch
}

fn main() -> Result<(), Box<dyn Error>> {
    let driver = DriverState::new();
    driver.windows_ffi.print_version();
    driver.pdb_store.print_default_information();

    Ok(())
}

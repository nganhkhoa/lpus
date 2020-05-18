use std::error::Error;
use std::str::{from_utf8};
use chrono::Utc;
use chrono::{DateTime};
use std::time::{UNIX_EPOCH, Duration};

use lpus::{
    driver_state::{DriverState /* , EprocessPoolChunk */}
};

#[allow(dead_code)]
fn to_str_time(time_ms: u64) -> String {
    if time_ms == 0 {
        return "".to_string();
    }
    let d = UNIX_EPOCH + Duration::from_millis(time_ms);
    let datetime = DateTime::<Utc>::from(d);
    let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();
    timestamp_str
}

fn main() -> Result<(), Box<dyn Error>> {
    // for windows admin require
    // https://github.com/nabijaczleweli/rust-embed-resource

    let mut driver = DriverState::new();
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    // let eprocess_scan_head = driver.scan_active_head(ntosbase)?;
    // let mut eprocess_list: Vec<EprocessPoolChunk> = Vec::new();
    driver.scan_pool(b"Proc", |pool_addr, header, data_addr| {
        let eprocess_name_offset = driver.pdb_store.get_offset_r("_EPROCESS.ImageFileName")?;
        let eprocess_create_time_offset = driver.pdb_store.get_offset_r("_EPROCESS.CreateTime")?;
        let eprocess_exit_time_offset = driver.pdb_store.get_offset_r("_EPROCESS.ExitTime")?;
        let eprocess_size = driver.pdb_store.get_offset_r("_EPROCESS.struct_size")?;

        let chunk_size = (header[2] as u64) * 16u64;
        let eprocess_valid_start = data_addr;
        let eprocess_valid_end = pool_addr + chunk_size - eprocess_size;
        let mut try_eprocess_ptr = eprocess_valid_start;

        let mut create_time = 0u64;
        let mut exit_time = 0u64;
        while try_eprocess_ptr <= eprocess_valid_end {
            driver.deref_addr(try_eprocess_ptr + eprocess_create_time_offset, &mut create_time);
            driver.deref_addr(try_eprocess_ptr + eprocess_exit_time_offset, &mut exit_time);
            // using heuristics to eliminate false positive
            if driver.windows_ffi.valid_process_time(create_time) {
                break;
            }
            try_eprocess_ptr += 0x4;        // search exhaustively
        }
        let mut image_name = [0u8; 15];
        driver.deref_addr(try_eprocess_ptr + eprocess_name_offset, &mut image_name);
        let eprocess_name = from_utf8(&image_name)?
                            .to_string()
                            .trim_end_matches(char::from(0))
                            .to_string();
        // eprocess_list.push(EprocessPoolChunk {
        //     pool_addr,
        //     eprocess_addr: try_eprocess_ptr,
        //     eprocess_name: eprocess_name,
        //     create_time: to_epoch(create_time),
        //     exit_time: to_epoch(exit_time)
        // });
        println!("pool: {} | eprocess: {}: {}", pool_addr, try_eprocess_ptr, eprocess_name);
        Ok(try_eprocess_ptr <= eprocess_valid_end)
    })?;

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

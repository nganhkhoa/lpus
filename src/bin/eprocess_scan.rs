use std::error::Error;
use std::str::{from_utf8};
use chrono::Utc;
use chrono::{DateTime};
use std::time::{UNIX_EPOCH, Duration};

use lpus::{
    driver_state::{DriverState /* , EprocessPoolChunk */},
    address::Address
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
    driver.scan_pool(b"Proc", "_EPROCESS", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let eprocess_size = driver.pdb_store.get_offset_r("_EPROCESS.struct_size")?;

        let eprocess_valid_start = &data_addr;
        let eprocess_valid_end = Address::from_base((pool_addr.address() + chunk_size) - eprocess_size);
        let mut try_eprocess_ptr = Address::from_base(eprocess_valid_start.address());

        while try_eprocess_ptr <= eprocess_valid_end {
            let create_time: u64 = driver.decompose(&try_eprocess_ptr, "_EPROCESS.CreateTime")?;
            if driver.windows_ffi.valid_process_time(create_time) {
                break;
            }
            try_eprocess_ptr += 0x4;        // search exhaustively
        }
        if try_eprocess_ptr > eprocess_valid_end {
            return Ok(false);
        }

        let eprocess_ptr = &try_eprocess_ptr;

        let pid: u64 = driver.decompose(eprocess_ptr, "_EPROCESS.UniqueProcessId")?;
        let ppid: u64 = driver.decompose(eprocess_ptr, "_EPROCESS.InheritedFromUniqueProcessId")?;
        let image_name: Vec<u8> = driver.decompose_array(eprocess_ptr, "_EPROCESS.ImageFileName", 15)?;
        let unicode_str_ptr = driver.address_of(eprocess_ptr, "_EPROCESS.ImageFilePointer.FileName")?;

        let eprocess_name =
            if let Ok(name) = from_utf8(&image_name) {
                name.to_string().trim_end_matches(char::from(0)).to_string()
            } else {
                "".to_string()
            };
        let binary_path =
            if unicode_str_ptr != 0 {
                driver.get_unicode_string(unicode_str_ptr, true)?
            } else {
                "".to_string()
            };

        println!("pool: {} | eprocess: {} | pid: {} | ppid: {} | name: {} | path: {}",
                 pool_addr, eprocess_ptr, pid, ppid, eprocess_name, binary_path);
        // eprocess_list.push(EprocessPoolChunk {
        //     pool_addr,
        //     eprocess_addr: try_eprocess_ptr,
        //     eprocess_name: eprocess_name,
        //     create_time: to_epoch(create_time),
        //     exit_time: to_epoch(exit_time)
        // });
        Ok(true)
    })?;

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}


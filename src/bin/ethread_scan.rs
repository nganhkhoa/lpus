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

    // let ethread_scan_head = driver.scan_active_head(ntosbase)?;
    // let mut ethread_list: Vec<EprocessPoolChunk> = Vec::new();
    driver.scan_pool(b"Thre", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let ethread_size = driver.pdb_store.get_offset_r("_ETHREAD.struct_size")?;
        let ethread_create_time_offset = driver.pdb_store.get_offset_r("_ETHREAD.CreateTime")?;
        let ethread_name_offset = driver.pdb_store.get_offset_r("_ETHREAD.ThreadName")?;
        // let ethread_exit_time_offset = driver.pdb_store.get_offset_r("_ETHREAD.ExitTime")?;

        let ethread_valid_start = data_addr;
        let ethread_valid_end = (pool_addr + chunk_size) - ethread_size;
        let mut try_ethread_ptr = ethread_valid_start;

        let mut create_time = 0u64;
        // let mut exit_time = 0u64;
        while try_ethread_ptr <= ethread_valid_end {
            driver.deref_addr(try_ethread_ptr + ethread_create_time_offset, &mut create_time);
            // driver.deref_addr(try_ethread_ptr + ethread_exit_time_offset, &mut exit_time);
            // using heuristics to eliminate false positive
            if driver.windows_ffi.valid_process_time(create_time) {
                break;
            }
            try_ethread_ptr += 0x4;        // search exhaustively
        }
        if try_ethread_ptr > ethread_valid_end {
            return Ok(false);
        }

        let mut thread_name_ptr = 0u64;
        driver.deref_addr(try_ethread_ptr + ethread_name_offset, &mut thread_name_ptr);
        let thread_name = if thread_name_ptr != 0 { driver.get_unicode_string(thread_name_ptr, true)? }
                          else { "".to_string() };

        println!("pool: 0x{:x} | ethread: 0x{:x} | {}", pool_addr, try_ethread_ptr, thread_name);
        Ok(true)
        // ethread_list.push(EprocessPoolChunk {
        //     pool_addr,
        //     ethread_addr: try_ethread_ptr,
        //     ethread_name: ethread_name,
        //     create_time: to_epoch(create_time),
        //     exit_time: to_epoch(exit_time)
        // });
    })?;

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}



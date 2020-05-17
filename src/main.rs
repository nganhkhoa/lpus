extern crate chrono;

mod pdb_store;
mod windows;
mod ioctl_protocol;
mod driver_state;

use std::error::Error;
use std::str::{from_utf8};
// use chrono::prelude::DateTime;
// use chrono::Utc;
// use chrono::{Local, DateTime};
// use std::time::{SystemTime, UNIX_EPOCH, Duration};

use pdb_store::parse_pdb;
use windows::WindowsFFI;
use driver_state::{DriverState, EprocessPoolChunk, to_epoch};

fn to_str_time(_time_ms: u64) -> String {
    // if time_ms == 0 {
    //     return "".to_string();
    // }
    // let d = UNIX_EPOCH + Duration::from_millis(time_ms);
    // let datetime = DateTime::<Utc>::from(d);
    // let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();
    // timestamp_str
    "".to_string()
}

fn main() -> Result<(), Box<dyn Error>> {
    // for windows admin require
    // https://github.com/nabijaczleweli/rust-embed-resource

    let mut driver = DriverState::new(parse_pdb(), WindowsFFI::new());
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    let ntosbase = driver.get_kernel_base()?;
    let pool_header_size = driver.pdb_store.get_offset_r("_POOL_HEADER.struct_size")?;

    let eprocess_tag: [u8; 4] = [80, 114, 111, 99]; // Proc
    let eprocess_name_offset = driver.pdb_store.get_offset_r("_EPROCESS.ImageFileName")?;
    let eprocess_create_time_offset = driver.pdb_store.get_offset_r("_EPROCESS.CreateTime")?;
    let eprocess_exit_time_offset = driver.pdb_store.get_offset_r("_EPROCESS.ExitTime")?;
    let eprocess_size = driver.pdb_store.get_offset_r("_EPROCESS.struct_size")?;

    let eprocess_scan_head = driver.scan_active_head(ntosbase)?;
    let mut eprocess_list: Vec<EprocessPoolChunk> = Vec::new();
    driver.scan_pool(ntosbase, eprocess_tag, |dr, pool_addr| {
        let mut pool = vec![0u8; pool_header_size as usize];
        dr.deref_addr_ptr(pool_addr, pool.as_mut_ptr(), pool_header_size);

        let chunk_size = (pool[2] as u64) * 16u64;
        let eprocess_valid_start = pool_addr + pool_header_size;
        let eprocess_valid_end = pool_addr + chunk_size - eprocess_size;
        let mut try_eprocess_ptr = eprocess_valid_start;

        let mut create_time = 0u64;
        let mut exit_time = 0u64;
        while try_eprocess_ptr <= eprocess_valid_end {
            dr.deref_addr(try_eprocess_ptr + eprocess_create_time_offset, &mut create_time);
            dr.deref_addr(try_eprocess_ptr + eprocess_exit_time_offset, &mut exit_time);
            if dr.windows_ffi.valid_process_time(create_time) {
                break;
            }
            try_eprocess_ptr += 0x4;        // search exhaustively
        }
        let mut image_name = [0u8; 15];
        dr.deref_addr(try_eprocess_ptr + eprocess_name_offset, &mut image_name);
        let eprocess_name = from_utf8(&image_name)?
                            .to_string()
                            .trim_end_matches(char::from(0))
                            .to_string();
        eprocess_list.push(EprocessPoolChunk {
            pool_addr,
            eprocess_addr: try_eprocess_ptr,
            eprocess_name: eprocess_name,
            create_time: to_epoch(create_time),
            exit_time: to_epoch(exit_time)
        });
        Ok(try_eprocess_ptr <= eprocess_valid_end)
    })?;

    let ethread_tag: [u8; 4] = [84, 104, 114, 101]; // Thre
    let ethread_create_time_offset = driver.pdb_store.get_offset_r("_ETHREAD.CreateTime")?;
    let ethread_exit_time_offset = driver.pdb_store.get_offset_r("_ETHREAD.ExitTime")?;
    let ethread_threadname_offset = driver.pdb_store.get_offset_r("_ETHREAD.TheadName")?;
    let ethread_size = driver.pdb_store.get_offset_r("_ETHREAD.struct_size")?;

    // let mut ethread_list: Vec<EprocessPoolChunk> = Vec::new();
    driver.scan_pool(ntosbase, ethread_tag, |dr, pool_addr| {
        let mut pool = vec![0u8; pool_header_size as usize];
        dr.deref_addr_ptr(pool_addr, pool.as_mut_ptr(), pool_header_size);

        let chunk_size = (pool[2] as u64) * 16u64;
        let ethread_valid_start = pool_addr + pool_header_size;
        let ethread_valid_end = pool_addr + chunk_size - ethread_size;
        let mut try_ethread_ptr = ethread_valid_start;

        let mut create_time = 0u64;
        let mut exit_time = 0u64;
        while try_ethread_ptr <= ethread_valid_end {
            dr.deref_addr(try_ethread_ptr + ethread_create_time_offset, &mut create_time);
            dr.deref_addr(try_ethread_ptr + ethread_exit_time_offset, &mut exit_time);
            if dr.windows_ffi.valid_process_time(create_time) {
                break;
            }
            try_ethread_ptr += 0x4;        // search exhaustively
        }
        let mut threadname_ptr = 0u64;
        dr.deref_addr(try_ethread_ptr + ethread_threadname_offset, &mut threadname_ptr);
        let threadname = dr.get_unicode_string(threadname_ptr)?;
        println!("threadname: {}", threadname);
        Ok(try_ethread_ptr <= ethread_valid_end)
    })?;

    // for result in &driver.eprocess_traverse_result {
    //     println!("- [{}] 0x{:x} {}",
    //              driver.pool_scan_result.contains(&result),
    //              result.eprocess_addr, result.eprocess_name);
    // }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

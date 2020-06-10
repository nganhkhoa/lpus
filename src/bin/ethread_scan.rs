use std::error::Error;
use chrono::Utc;
use chrono::{DateTime};
use std::time::{UNIX_EPOCH, Duration};

use lpus::{
    driver_state::{DriverState}
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

    driver.scan_pool(b"Thre", "_ETHREAD", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let ethread_size = driver.pdb_store.get_offset_r("_ETHREAD.struct_size")?;
        let ethread_valid_start = &data_addr;
        let ethread_valid_end = (pool_addr.clone() + chunk_size) - ethread_size;
        let mut try_ethread_ptr = ethread_valid_start.clone();

        while try_ethread_ptr <= ethread_valid_end {
            let create_time: u64 = driver.decompose(&try_ethread_ptr, "_ETHREAD.CreateTime")?;
            if driver.windows_ffi.valid_process_time(create_time) {
                break;
            }
            try_ethread_ptr += 0x4;        // search exhaustively
        }
        if try_ethread_ptr > ethread_valid_end {
            return Ok(false);
        }

        let ethread_ptr = &try_ethread_ptr;

        let pid: u64 = driver.decompose(ethread_ptr, "_ETHREAD.Cid.UniqueProcess")?;
        let tid: u64 = driver.decompose(ethread_ptr, "_ETHREAD.Cid.UniqueThread")?;
        let unicode_str_ptr: u64 = driver.address_of(ethread_ptr, "_ETHREAD.ThreadName")?;

        let thread_name =
            if unicode_str_ptr == 0 {
                "".to_string()
            }
            else if let Ok(name) = driver.get_unicode_string(unicode_str_ptr, true) {
                name
            }
            else {
                "".to_string()
            };

        println!("pool: {} | ethread: {} | pid: {} | tid: {} | {}",
                 pool_addr, ethread_ptr, pid, tid, thread_name);
        Ok(true)
    })?;

    println!("Scan _KMUTANT");

    // scan for mutants, also reveals Threads
    // driver.scan_pool(b"Muta", "_KMUTANT", |pool_addr, header, data_addr| {
    //     let chunk_size = (header[2] as u64) * 16u64;
    //
    //     println!("Mutant pool size {}", chunk_size);
    //     return Ok(false);
    //
    //     let kmutant_size = driver.pdb_store.get_offset_r("_KMUTANT.struct_size")?;
    //     let kmutant_ownerthread_offset = driver.pdb_store.get_offset_r("_KMUTANT.OwnerThread")?;
    //     let ethread_name_offset = driver.pdb_store.get_offset_r("_ETHREAD.ThreadName")?;
    //
    //     let kmutant_valid_start = data_addr;
    //     let kmutant_valid_end = (pool_addr + chunk_size) - kmutant_size;
    //     let mut try_kmutant_ptr = kmutant_valid_start;
    //
    //     while try_kmutant_ptr <= kmutant_valid_end {
    //         // TODO: Create check
    //         try_kmutant_ptr += 0x4;        // search exhaustively
    //     }
    //     if try_kmutant_ptr > kmutant_valid_end {
    //         return Ok(false);
    //     }
    //
    //     let kmutant_ptr = try_kmutant_ptr;
    //     let mut ethread_ptr = 0u64;
    //     let mut thread_name_ptr = 0u64;
    //     let mut pid = 0u64;
    //     let mut tid = 0u64;
    //
    //     driver.deref_addr(kmutant_ptr + kmutant_ownerthread_offset, &mut ethread_ptr);
    //     let pid_ptr = driver.pdb_store.addr_decompose(ethread_ptr, "_ETHREAD.Cid.UniqueProcess")?;
    //     let tid_ptr = driver.pdb_store.addr_decompose(ethread_ptr, "_ETHREAD.Cid.UniqueThread")?;
    //
    //     driver.deref_addr(pid_ptr, &mut pid);
    //     driver.deref_addr(tid_ptr, &mut tid);
    //     driver.deref_addr(ethread_ptr + ethread_name_offset, &mut thread_name_ptr);
    //
    //     let thread_name =
    //         if thread_name_ptr != 0 { driver.get_unicode_string(thread_name_ptr, true)? }
    //         else { "".to_string() };
    //
    //     println!("pool: 0x{:x} | kmutant: 0x{:x} | pid: {} | tid: {} | {}",
    //              pool_addr, kmutant_ptr, pid, tid, thread_name);
    //     Ok(true)
    //     // kmutant_list.push(EprocessPoolChunk {
    //     //     pool_addr,
    //     //     kmutant_addr: try_kmutant_ptr,
    //     //     kmutant_name: kmutant_name,
    //     //     create_time: to_epoch(create_time),
    //     //     exit_time: to_epoch(exit_time)
    //     // });
    // })?;
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}



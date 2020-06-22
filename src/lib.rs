extern crate chrono;
extern crate app_dirs;

pub mod pdb_store;
pub mod windows;
pub mod ioctl_protocol;
pub mod driver_state;
pub mod address;

use std::error::Error;
use std::str::{from_utf8};
use serde_json::{json, Value};
use driver_state::DriverState;
use address::Address;

type BoxResult<T> = Result<T, Box<dyn Error>>;

pub fn scan_eprocess(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();
    driver.scan_pool(b"Proc", "_EPROCESS", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let eprocess_size = driver.pdb_store.get_offset_r("_EPROCESS.struct_size")?;

        let eprocess_valid_start = &data_addr;
        let eprocess_valid_end = (pool_addr.clone() + chunk_size) - eprocess_size;
        let mut try_eprocess_ptr = eprocess_valid_start.clone();

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
        let binary_path = driver.get_unicode_string(unicode_str_ptr)
                          .unwrap_or("".to_string());

        result.push(json!({
            "pool": format!("0x{:x}", pool_addr.address()),
            "address": format!("0x{:x}", eprocess_ptr.address()),
            "type": "_EPROCESS",
            "pid": pid,
            "ppid": ppid,
            "name": eprocess_name,
            "path": binary_path
        }));
        Ok(true)
    })?;
    Ok(result)
}

pub fn scan_file(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    driver.scan_pool(b"File", "_FILE_OBJECT", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let fob_size = driver.pdb_store.get_offset_r("_FILE_OBJECT.struct_size")?;
        let valid_end = (pool_addr.clone() + chunk_size) - fob_size;
        let mut try_ptr = data_addr;

        while try_ptr <= valid_end {
            let ftype: u16 = driver.decompose(&try_ptr, "_FILE_OBJECT.Type")?;
            let size: u16 = driver.decompose(&try_ptr, "_FILE_OBJECT.Size")?;
            if (size as u64) == fob_size && ftype == 5u16 {
                break;
            }
            try_ptr += 0x4;        // search exhaustively
        }
        if try_ptr > valid_end {
            return Ok(false);
        }

        let fob_addr = &try_ptr;
        let read_ok: u8 = driver.decompose(fob_addr, "_FILE_OBJECT.ReadAccess")?;
        let write_ok: u8 = driver.decompose(fob_addr, "_FILE_OBJECT.WriteAccess")?;
        let delete_ok: u8 = driver.decompose(fob_addr, "_FILE_OBJECT.DeleteAccess")?;
        let share_read_ok: u8 = driver.decompose(fob_addr, "_FILE_OBJECT.SharedRead")?;
        let share_write_ok: u8 = driver.decompose(fob_addr, "_FILE_OBJECT.SharedWrite")?;
        let share_delete_ok: u8 = driver.decompose(fob_addr, "_FILE_OBJECT.SharedDelete")?;
        let filename_ptr = driver.address_of(fob_addr, "_FILE_OBJECT.FileName")?;
        let devicename_ptr: u64 = driver.address_of(fob_addr, "_FILE_OBJECT.DeviceObject.DriverObject.DriverName")?;
        let hardware_ptr: u64 = driver.decompose(fob_addr, "_FILE_OBJECT.DeviceObject.DriverObject.HardwareDatabase")?;

        let filename =
            if read_ok == 0 {
                "[NOT READABLE]".to_string()
            }
            else if let Ok(n) = driver.get_unicode_string(filename_ptr) {
                n
            }
            else {
                "[NOT A VALID _UNICODE_STRING]".to_string()
            };
        let devicename = driver.get_unicode_string(devicename_ptr)
                         .unwrap_or("".to_string());
        let hardware = driver.get_unicode_string(hardware_ptr)
                       .unwrap_or("".to_string());
        result.push(json!({
            "pool": format!("0x{:x}", pool_addr.address()),
            "address": format!("0x{:x}", fob_addr.address()),
            "type": "_FILE_OBJECT",
            "path": filename,
            "device": devicename,
            "hardware": hardware,
            "access": {
                "r": read_ok == 1,
                "w": write_ok == 1,
                "d": delete_ok == 1,
                "R": share_read_ok == 1,
                "W": share_write_ok == 1,
                "D": share_delete_ok == 1
            }
        }));
        Ok(true)
    })?;

    Ok(result)
}

pub fn scan_ethread(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

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
            if let Ok(name) = driver.get_unicode_string(unicode_str_ptr) {
                name
            }
            else {
                "".to_string()
            };

        result.push(json!({
            "pool": format!("0x{:x}", pool_addr.address()),
            "address": format!("0x{:x}", ethread_ptr.address()),
            "type": "_ETHREAD",
            "pid": pid,
            "tid": tid,
            "name": thread_name
        }));
        Ok(true)
    })?;

    Ok(result)
}

// Unstable, do not use
pub fn scan_mutant(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let ntosbase = driver.get_kernel_base();
    let [start, end] = driver.get_nonpaged_range(&ntosbase)?;

    driver.scan_pool(b"Muta", "_KMUTANT", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let kmutant_size = driver.pdb_store.get_offset_r("_KMUTANT.struct_size")?;

        let kmutant_valid_start = data_addr;
        let kmutant_valid_end = (pool_addr.clone() + chunk_size) - kmutant_size;
        let mut try_kmutant_ptr = kmutant_valid_start.clone();

        while try_kmutant_ptr <= kmutant_valid_end {
            // TODO: Stronger constrain
            let kthread_ptr = driver.address_of(&try_kmutant_ptr, "_KMUTANT.OwnerThread")?;
            if kthread_ptr > start.address() && kthread_ptr < end.address() {
                break;
            }
            try_kmutant_ptr += 0x4;        // search exhaustively
        }
        if try_kmutant_ptr > kmutant_valid_end {
            return Ok(false);
        }

        let kmutant_ptr = try_kmutant_ptr;
        let ethread_ptr = Address::from_base(driver.address_of(&kmutant_ptr, "_KMUTANT.OwnerThread")?);

        let pid: u64 = driver.decompose(&ethread_ptr, "_ETHREAD.Cid.UniqueProcess")?;
        let tid: u64 = driver.decompose(&ethread_ptr, "_ETHREAD.Cid.UniqueThread")?;
        let unicode_str_ptr: u64 = driver.address_of(&ethread_ptr, "_ETHREAD.ThreadName")?;

        let thread_name =
            if let Ok(name) = driver.get_unicode_string(unicode_str_ptr) {
                name
            }
            else {
                "".to_string()
            };

        result.push(json!({
            "pool": format!("0x{:x}", pool_addr.address()),
            "address": format!("0x{:x}", ethread_ptr.address()),
            "type": "_KMUTANT",
            "pid": pid,
            "tid": tid,
            "name": thread_name
        }));
        Ok(true)
    })?;

    Ok(result)
}

pub fn scan_driver(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    driver.scan_pool(b"Driv", "_DRIVER_OBJECT", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let dob_size = driver.pdb_store.get_offset_r("_DRIVER_OBJECT.struct_size")?;
        let valid_end = (pool_addr.clone() + chunk_size) - dob_size;
        let mut try_ptr = data_addr;

        while try_ptr <= valid_end {
            // No documentation on type constrain
            // let ftype: u16 = driver.decompose(&try_ptr, "_DRIVER_OBJECT.Type")?;
            let size: u16 = driver.decompose(&try_ptr, "_DRIVER_OBJECT.Size")?;
            if (size as u64) == dob_size /* && ftype == 5u16 */ {
                break;
            }
            try_ptr += 0x4;        // search exhaustively
        }
        if try_ptr > valid_end {
            return Ok(false);
        }
        let dob_addr = &try_ptr;

        let devicename_ptr = driver.address_of(dob_addr, "_DRIVER_OBJECT.DriverName")?;
        let hardware_ptr: u64 = driver.decompose(dob_addr, "_DRIVER_OBJECT.HardwareDatabase")?;
        let major_function: Vec<u64> = driver.decompose_array(dob_addr, "_DRIVER_OBJECT.MajorFunction", 28)?;

        let devicename = driver.get_unicode_string(devicename_ptr)
                         .unwrap_or("".to_string());
        let hardware = driver.get_unicode_string(hardware_ptr)
                       .unwrap_or("".to_string());
        result.push(json!({
            "pool": format!("0x{:x}", pool_addr.address()),
            "address": format!("0x{:x}", dob_addr.address()),
            "type": "_DRIVER_OBJECT",
            "device": devicename,
            "hardware": hardware,
            "major_function": major_function.into_iter()
                              .map(|func| format!("0x{:x}", func))
                              .collect::<Vec<String>>()
        }));
        Ok(true)
    })?;

    Ok(result)
}

pub fn scan_kernel_module(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    driver.scan_pool(b"MmLd", "_KLDR_DATA_TABLE_ENTRY", |pool_addr, _, data_addr| {
        // By reversing, this structure does not have any header
        let mod_addr = &data_addr;

        let dllbase: u64 = driver.decompose(mod_addr, "_KLDR_DATA_TABLE_ENTRY.DllBase")?;
        let entry: u64 = driver.decompose(mod_addr, "_KLDR_DATA_TABLE_ENTRY.EntryPoint")?;
        let size: u64 = driver.decompose(mod_addr, "_KLDR_DATA_TABLE_ENTRY.SizeOfImage")?;
        let fullname_ptr = driver.address_of(mod_addr, "_KLDR_DATA_TABLE_ENTRY.FullDllName")?;
        let basename_ptr = driver.address_of(mod_addr, "_KLDR_DATA_TABLE_ENTRY.BaseDllName")?;

        let fullname = driver.get_unicode_string(fullname_ptr)
                       .unwrap_or("".to_string());
        let basename = driver.get_unicode_string(basename_ptr)
                       .unwrap_or("".to_string());
        result.push(json!({
            "pool": format!("0x{:x}", pool_addr.address()),
            "address": format!("0x{:x}", mod_addr.address()),
            "type": "_KLDR_DATA_TABLE_ENTRY",
            "dllbase": format!("0x{:x}", dllbase),
            "entry": format!("0x{:x}", entry),
            "size": format!("0x{:x}", size),
            "FullName": fullname,
            "BaseName": basename
        }));
        Ok(true)
    })?;

    Ok(result)
}

pub fn traverse_loadedmodulelist(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let ntosbase = driver.get_kernel_base();
    let module_list_head = ntosbase + driver.pdb_store.get_offset_r("PsLoadedModuleList")?;

    let mut ptr: u64 = driver.decompose(&module_list_head, "_LIST_ENTRY.Flink")?;
    while ptr != module_list_head.address() {
        let mod_addr = Address::from_base(ptr);

        let dllbase: u64 = driver.decompose(&mod_addr, "_KLDR_DATA_TABLE_ENTRY.DllBase")?;
        let entry: u64 = driver.decompose(&mod_addr, "_KLDR_DATA_TABLE_ENTRY.EntryPoint")?;
        let size: u64 = driver.decompose(&mod_addr, "_KLDR_DATA_TABLE_ENTRY.SizeOfImage")?;
        let fullname_ptr = driver.address_of(&mod_addr, "_KLDR_DATA_TABLE_ENTRY.FullDllName")?;
        let basename_ptr = driver.address_of(&mod_addr, "_KLDR_DATA_TABLE_ENTRY.BaseDllName")?;

        let fullname = driver.get_unicode_string(fullname_ptr)
                       .unwrap_or("".to_string());
        let basename = driver.get_unicode_string(basename_ptr)
                       .unwrap_or("".to_string());
        result.push(json!({
            "address": format!("0x{:x}", mod_addr.address()),
            "type": "_KLDR_DATA_TABLE_ENTRY",
            "dllbase": format!("0x{:x}", dllbase),
            "entry": format!("0x{:x}", entry),
            "size": format!("0x{:x}", size),
            "FullName": fullname,
            "BaseName": basename
        }));

        ptr = driver.decompose(&mod_addr, "_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks.Flink")?;
    }

    Ok(result)
}

// dx Debugger.Utility.Collections.FromListEntry( *(nt!_LIST_ENTRY*)&(nt!PsActiveProcessHead), "nt!_EPROCESS", "ActiveProcessLinks")
pub fn traverse_activehead(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let ntosbase = driver.get_kernel_base();
    let process_list_head = ntosbase + driver.pdb_store.get_offset_r("PsActiveProcessHead")?;
    let eprocess_listentry_offset = driver.pdb_store.get_offset_r("_EPROCESS.ActiveProcessLinks")?;

    let mut ptr: u64 = driver.decompose(&process_list_head, "_LIST_ENTRY.Flink")?;
    while ptr != process_list_head.address() {
        let eprocess_ptr = Address::from_base(ptr - eprocess_listentry_offset);

        let pid: u64 = driver.decompose(&eprocess_ptr, "_EPROCESS.UniqueProcessId")?;
        let ppid: u64 = driver.decompose(&eprocess_ptr, "_EPROCESS.InheritedFromUniqueProcessId")?;
        let image_name: Vec<u8> = driver.decompose_array(&eprocess_ptr, "_EPROCESS.ImageFileName", 15)?;
        let unicode_str_ptr = driver.address_of(&eprocess_ptr, "_EPROCESS.ImageFilePointer.FileName")?;

        let eprocess_name =
            if let Ok(name) = from_utf8(&image_name) {
                name.to_string().trim_end_matches(char::from(0)).to_string()
            } else {
                "".to_string()
            };
        let binary_path = driver.get_unicode_string(unicode_str_ptr)
                          .unwrap_or("".to_string());

        result.push(json!({
            "address": format!("0x{:x}", &eprocess_ptr.address()),
            "type": "_EPROCESS",
            "pid": pid,
            "ppid": ppid,
            "name": eprocess_name,
            "path": binary_path
        }));

        ptr = driver.decompose(&eprocess_ptr, "_EPROCESS.ActiveProcessLinks.Flink")?;
    }

    Ok(result)
}

// TODO: where is afd!
// dx Debugger.Utility.Collections.FromListEntry( *(nt!_LIST_ENTRY*)&(afd!AfdEndpointListHead), "nt!_EPROCESS", "ActiveProcessLinks")
// pub fn traverse_afdendpoint(driver: &DriverState) -> BoxResult<Vec<Value>> {
//     let mut result: Vec<Value> = Vec::new();
//
//     let ntosbase = driver.get_kernel_base();
//     let process_list_head = ntosbase + driver.pdb_store.get_offset_r("PsActiveProcessHead")?;
//     let eprocess_listentry_offset = driver.pdb_store.get_offset_r("_EPROCESS.ActiveProcessLinks")?;
//
//     let mut ptr: u64 = driver.decompose(&process_list_head, "_LIST_ENTRY.Flink")?;
//     while ptr != process_list_head.address() {
//         let eprocess_ptr = Address::from_base(ptr - eprocess_listentry_offset);
//
//         let pid: u64 = driver.decompose(&eprocess_ptr, "_EPROCESS.UniqueProcessId")?;
//         let ppid: u64 = driver.decompose(&eprocess_ptr, "_EPROCESS.InheritedFromUniqueProcessId")?;
//         let image_name: Vec<u8> = driver.decompose_array(&eprocess_ptr, "_EPROCESS.ImageFileName", 15)?;
//         let unicode_str_ptr = driver.address_of(&eprocess_ptr, "_EPROCESS.ImageFilePointer.FileName")?;
//
//         let eprocess_name =
//             if let Ok(name) = from_utf8(&image_name) {
//                 name.to_string().trim_end_matches(char::from(0)).to_string()
//             } else {
//                 "".to_string()
//             };
//         let binary_path = driver.get_unicode_string(unicode_str_ptr)
//                           .unwrap_or("".to_string());
//
//         result.push(json!({
//             "address": format!("0x{:x}", &eprocess_ptr.address()),
//             "type": "_EPROCESS",
//             "pid": pid,
//             "ppid": ppid,
//             "name": eprocess_name,
//             "path": binary_path
//         }));
//
//         ptr = driver.decompose(&eprocess_ptr, "_EPROCESS.ActiveProcessLinks.Flink")?;
//     }
//
//     Ok(result)
// }

// dx Debugger.Utility.Collections.FromListEntry( *(nt!_LIST_ENTRY*)&(nt!KiProcessListHead), "nt!_KPROCESS", "ProcessListEntry").Select( p => new {Process = (nt!_EPROCESS*)&p )
pub fn traverse_kiprocesslist(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let ntosbase = driver.get_kernel_base();
    let process_list_head = ntosbase + driver.pdb_store.get_offset_r("KiProcessListHead")?;
    let eprocess_listentry_offset = driver.pdb_store.get_offset_r("_KPROCESS.ProcessListEntry")?;

    let mut ptr: u64 = driver.decompose(&process_list_head, "_LIST_ENTRY.Flink")?;
    while ptr != process_list_head.address() {
        let eprocess_ptr = Address::from_base(ptr - eprocess_listentry_offset);

        let pid: u64 = driver.decompose(&eprocess_ptr, "_EPROCESS.UniqueProcessId")?;
        let ppid: u64 = driver.decompose(&eprocess_ptr, "_EPROCESS.InheritedFromUniqueProcessId")?;
        let image_name: Vec<u8> = driver.decompose_array(&eprocess_ptr, "_EPROCESS.ImageFileName", 15)?;
        let unicode_str_ptr = driver.address_of(&eprocess_ptr, "_EPROCESS.ImageFilePointer.FileName")?;

        let eprocess_name =
            if let Ok(name) = from_utf8(&image_name) {
                name.to_string().trim_end_matches(char::from(0)).to_string()
            } else {
                "".to_string()
            };
        let binary_path = driver.get_unicode_string(unicode_str_ptr)
                          .unwrap_or("".to_string());

        result.push(json!({
            "address": format!("0x{:x}", &eprocess_ptr.address()),
            "type": "_EPROCESS",
            "pid": pid,
            "ppid": ppid,
            "name": eprocess_name,
            "path": binary_path
        }));

        ptr = driver.decompose(&eprocess_ptr, "_KPROCESS.ProcessListEntry.Flink")?;
    }

    Ok(result)
}

// dx Debugger.Utility.Collections.FromListEntry(*(nt!_LIST_ENTRY*)&nt!HandleTableListHead, "nt!_HANDLE_TABLE", "HandleTableList").Where(h => h.QuotaProcess != 0).Select( qp => new {Process= qp.QuotaProcess} )
pub fn traverse_handletable(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let ntosbase = driver.get_kernel_base();
    let process_list_head = ntosbase + driver.pdb_store.get_offset_r("HandleTableListHead")?;
    let handle_list_offset = driver.pdb_store.get_offset_r("_HANDLE_TABLE.HandleTableList")?;

    let mut ptr: u64 = driver.decompose(&process_list_head, "_LIST_ENTRY.Flink")?;
    while ptr != process_list_head.address() {
        let handle_ptr = Address::from_base(ptr - handle_list_offset);
        let quota_process: u64 = driver.decompose(&handle_ptr, "_HANDLE_TABLE.QuotaProcess")?;

        if quota_process != 0 {
            let eprocess_ptr = Address::from_base(quota_process);
            let pid: u64 = driver.decompose(&eprocess_ptr, "_EPROCESS.UniqueProcessId")?;
            let ppid: u64 = driver.decompose(&eprocess_ptr, "_EPROCESS.InheritedFromUniqueProcessId")?;
            let image_name: Vec<u8> = driver.decompose_array(&eprocess_ptr, "_EPROCESS.ImageFileName", 15)?;
            let unicode_str_ptr = driver.address_of(&eprocess_ptr, "_EPROCESS.ImageFilePointer.FileName")?;

            let eprocess_name =
                if let Ok(name) = from_utf8(&image_name) {
                    name.to_string().trim_end_matches(char::from(0)).to_string()
                } else {
                    "".to_string()
                };
            let binary_path = driver.get_unicode_string(unicode_str_ptr)
                            .unwrap_or("".to_string());

            result.push(json!({
                "address": format!("0x{:x}", &eprocess_ptr.address()),
                "type": "_EPROCESS",
                "pid": pid,
                "ppid": ppid,
                "name": eprocess_name,
                "path": binary_path
            }));
        }

        ptr = driver.decompose(&handle_ptr, "_HANDLE_TABLE.HandleTableList.Flink")?;
    }

    Ok(result)
}

pub fn traverse_unloadeddrivers(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();
    let ntosbase = driver.get_kernel_base();
    let unload_array_ptr = ntosbase.clone() + driver.pdb_store.get_offset_r("MmUnloadedDrivers")?;
    let num_unload_ptr = ntosbase.clone() + driver.pdb_store.get_offset_r("MmLastUnloadedDriver")?;

    let unload_array = driver.deref_addr_new::<u64>(unload_array_ptr.address());
    if unload_array == 0 {
        return Err("The unload driver list is null".into());
    }

    // by reversing MmLocateUnloadedDriver
    let num_unload = driver.deref_addr_new::<u32>(num_unload_ptr.address()) as u64;
    let bound =
        if num_unload > 0x32 { 0x32 }
        else { num_unload };
    let drivers = (0..bound).map(|i| Address::from_base(unload_array + (i * 0x28)));

    for driver_addr in drivers {
        let name = driver.get_unicode_string(driver_addr.address()).unwrap_or("".to_string());
        let start_addr: u64 = driver.decompose(&driver_addr, "_UNLOADED_DRIVERS.StartAddress")?;
        let end_addr: u64 = driver.decompose(&driver_addr, "_UNLOADED_DRIVERS.EndAddress")?;
        let current_time: u64 = driver.decompose(&driver_addr, "_UNLOADED_DRIVERS.CurrentTime")?;

        result.push(json!({
            "address": format!("0x{:x}", driver_addr.address()),
            "type": "_UNLOADED_DRIVERS",
            "name": name,
            "start_addr": format!("0x{:x}", start_addr),
            "end_addr": format!("0x{:x}", end_addr),
            "current_time": driver.windows_ffi.to_epoch(current_time)
        }));
    }

    Ok(result)
}

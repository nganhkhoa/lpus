extern crate app_dirs;
extern crate chrono;

pub mod address;
pub mod commands;
pub mod driver_state;
pub mod ioctl_protocol;
pub mod object;
pub mod paging_structs;
pub mod paging_traverse;
pub mod pdb_store;
pub mod utils;
pub mod windows;

use app_dirs::AppInfo;
use chrono::{DateTime, Local, TimeZone};
use serde_json::{json, Value};
use std::error::Error;

use address::Address;
use driver_state::DriverState;
use object::*;
use utils::*;

type BoxResult<T> = Result<T, Box<dyn Error>>;

pub const APP_INFO: AppInfo = AppInfo {
    name: "lpus",
    author: "nganhkhoa",
};

pub fn to_epoch(filetime: u64) -> DateTime<Local> {
    // return seconds from epoch
    let windows_epoch_diff = 11_644_473_600_000 * 10_000;
    if filetime < windows_epoch_diff {
        return Local.timestamp(0, 0);
    }
    let filetime_epoch = (filetime - windows_epoch_diff) / 10_000_000;
    Local.timestamp(filetime_epoch as i64, 0)
}

pub fn get_irp_name(idx: usize) -> String {
    let irp_names = vec![
        "IRP_MJ_CREATE",
        "IRP_MJ_CREATE_NAMED_PIPE",
        "IRP_MJ_CLOSE",
        "IRP_MJ_READ",
        "IRP_MJ_WRITE",
        "IRP_MJ_QUERY_INFORMATION",
        "IRP_MJ_SET_INFORMATION",
        "IRP_MJ_QUERY_EA",
        "IRP_MJ_SET_EA",
        "IRP_MJ_FLUSH_BUFFERS",
        "IRP_MJ_QUERY_VOLUME_INFORMATION",
        "IRP_MJ_SET_VOLUME_INFORMATION",
        "IRP_MJ_DIRECTORY_CONTROL",
        "IRP_MJ_FILE_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CONTROL",
        "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        "IRP_MJ_SHUTDOWN",
        "IRP_MJ_LOCK_CONTROL",
        "IRP_MJ_CLEANUP",
        "IRP_MJ_CREATE_MAILSLOT",
        "IRP_MJ_QUERY_SECURITY",
        "IRP_MJ_SET_SECURITY",
        "IRP_MJ_POWER",
        "IRP_MJ_SYSTEM_CONTROL",
        "IRP_MJ_DEVICE_CHANGE",
        "IRP_MJ_QUERY_QUOTA",
        "IRP_MJ_SET_QUOTA",
        "IRP_MJ_PNP",
    ]
    .iter()
    .map(|x| x.to_string())
    .collect::<Vec<String>>();

    if let Some(name) = irp_names.get(idx) {
        name.clone()
    } else {
        "UNKNOWN".to_string()
    }
}

fn get_device_type(typ: u32) -> String {
    match typ {
        0x00000027 => "FILE_DEVICE_8042_PORT",
        0x00000032 => "FILE_DEVICE_ACPI",
        0x00000029 => "FILE_DEVICE_BATTERY",
        0x00000001 => "FILE_DEVICE_BEEP",
        0x0000002a => "FILE_DEVICE_BUS_EXTENDER",
        0x00000002 => "FILE_DEVICE_CD_ROM",
        0x00000003 => "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
        0x00000030 => "FILE_DEVICE_CHANGER",
        0x00000004 => "FILE_DEVICE_CONTROLLER",
        0x00000005 => "FILE_DEVICE_DATALINK",
        0x00000006 => "FILE_DEVICE_DFS",
        0x00000035 => "FILE_DEVICE_DFS_FILE_SYSTEM",
        0x00000036 => "FILE_DEVICE_DFS_VOLUME",
        0x00000007 => "FILE_DEVICE_DISK",
        0x00000008 => "FILE_DEVICE_DISK_FILE_SYSTEM",
        0x00000033 => "FILE_DEVICE_DVD",
        0x00000009 => "FILE_DEVICE_FILE_SYSTEM",
        0x0000003a => "FILE_DEVICE_FIPS",
        0x00000034 => "FILE_DEVICE_FULLSCREEN_VIDEO",
        0x0000000a => "FILE_DEVICE_INPORT_PORT",
        0x0000000b => "FILE_DEVICE_KEYBOARD",
        0x0000002f => "FILE_DEVICE_KS",
        0x00000039 => "FILE_DEVICE_KSEC",
        0x0000000c => "FILE_DEVICE_MAILSLOT",
        0x0000002d => "FILE_DEVICE_MASS_STORAGE",
        0x0000000d => "FILE_DEVICE_MIDI_IN",
        0x0000000e => "FILE_DEVICE_MIDI_OUT",
        0x0000002b => "FILE_DEVICE_MODEM",
        0x0000000f => "FILE_DEVICE_MOUSE",
        0x00000010 => "FILE_DEVICE_MULTI_UNC_PROVIDER",
        0x00000011 => "FILE_DEVICE_NAMED_PIPE",
        0x00000012 => "FILE_DEVICE_NETWORK",
        0x00000013 => "FILE_DEVICE_NETWORK_BROWSER",
        0x00000014 => "FILE_DEVICE_NETWORK_FILE_SYSTEM",
        0x00000028 => "FILE_DEVICE_NETWORK_REDIRECTOR",
        0x00000015 => "FILE_DEVICE_NULL",
        0x00000016 => "FILE_DEVICE_PARALLEL_PORT",
        0x00000017 => "FILE_DEVICE_PHYSICAL_NETCARD",
        0x00000018 => "FILE_DEVICE_PRINTER",
        0x00000019 => "FILE_DEVICE_SCANNER",
        0x0000001c => "FILE_DEVICE_SCREEN",
        0x00000037 => "FILE_DEVICE_SERENUM",
        0x0000001a => "FILE_DEVICE_SERIAL_MOUSE_PORT",
        0x0000001b => "FILE_DEVICE_SERIAL_PORT",
        0x00000031 => "FILE_DEVICE_SMARTCARD",
        0x0000002e => "FILE_DEVICE_SMB",
        0x0000001d => "FILE_DEVICE_SOUND",
        0x0000001e => "FILE_DEVICE_STREAMS",
        0x0000001f => "FILE_DEVICE_TAPE",
        0x00000020 => "FILE_DEVICE_TAPE_FILE_SYSTEM",
        0x00000038 => "FILE_DEVICE_TERMSRV",
        0x00000021 => "FILE_DEVICE_TRANSPORT",
        0x00000022 => "FILE_DEVICE_UNKNOWN",
        0x0000002c => "FILE_DEVICE_VDM",
        0x00000023 => "FILE_DEVICE_VIDEO",
        0x00000024 => "FILE_DEVICE_VIRTUAL_DISK",
        0x00000025 => "FILE_DEVICE_WAVE_IN",
        0x00000026 => "FILE_DEVICE_WAVE_OUT",
        _ => "UNKNOWN",
    }
    .to_string()
}

pub fn scan_eprocess(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();
    let tag = if driver.use_old_tag() {
        b"Pro\xe3"
    } else {
        b"Proc"
    };
    driver.scan_pool(tag, "_EPROCESS", |pool_addr, header, data_addr| {
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
            try_eprocess_ptr += 0x4; // search exhaustively
        }
        if try_eprocess_ptr > eprocess_valid_end {
            return Ok(false);
        }

        result.push(make_eprocess(driver, &try_eprocess_ptr)?);
        Ok(true)
    })?;
    Ok(result)
}

pub fn scan_file(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let tag = if driver.use_old_tag() {
        b"Fil\xe5"
    } else {
        b"File"
    };
    driver.scan_pool(tag, "_FILE_OBJECT", |pool_addr, header, data_addr| {
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
            try_ptr += 0x4; // search exhaustively
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
        let devicename_ptr: u64 = driver.address_of(
            fob_addr,
            "_FILE_OBJECT.DeviceObject.DriverObject.DriverName",
        )?;
        let hardware_ptr: u64 = driver.decompose(
            fob_addr,
            "_FILE_OBJECT.DeviceObject.DriverObject.HardwareDatabase",
        )?;

        let filename = if read_ok == 0 {
            "[NOT READABLE]".to_string()
        } else if let Ok(n) = driver.get_unicode_string(filename_ptr) {
            n
        } else {
            "[NOT A VALID _UNICODE_STRING]".to_string()
        };
        let devicename = driver
            .get_unicode_string(devicename_ptr)
            .unwrap_or("".to_string());
        let hardware = driver
            .get_unicode_string(hardware_ptr)
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

    let tag = if driver.use_old_tag() {
        b"Thr\xe5"
    } else {
        b"Thre"
    };
    driver.scan_pool(tag, "_ETHREAD", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let object_header_size = driver
            .pdb_store
            .get_offset_r("_OBJECT_HEADER.struct_size")?;
        let header_size = driver.pdb_store.get_offset_r("_POOL_HEADER.struct_size")?;
        let ethread_size = driver.pdb_store.get_offset_r("_ETHREAD.struct_size")?;
        let ethread_valid_start = &data_addr;
        let ethread_valid_end = (pool_addr.clone() + chunk_size) - ethread_size;
        let mut try_ethread_ptr = ethread_valid_start.clone();

        if chunk_size == header_size + object_header_size + ethread_size {
            try_ethread_ptr = ethread_valid_end.clone();
        } else {
            while try_ethread_ptr <= ethread_valid_end {
                let create_time: u64 = driver.decompose(&try_ethread_ptr, "_ETHREAD.CreateTime")?;
                if driver.windows_ffi.valid_process_time(create_time) {
                    break;
                }
                try_ethread_ptr += 0x4; // search exhaustively
            }
            if try_ethread_ptr > ethread_valid_end {
                return Ok(false);
            }
        }

        result.push(make_ethread(driver, &try_ethread_ptr)?);
        Ok(true)
    })?;

    Ok(result)
}

// Unstable, do not use
// pub fn scan_mutant(driver: &DriverState) -> BoxResult<Vec<Value>> {
//     let mut result: Vec<Value> = Vec::new();
//
//     let ntosbase = driver.get_kernel_base();
//     let [start, end] = driver.get_nonpaged_range(&ntosbase)?;
//
//     let tag =
//         if driver.use_old_tag() { b"Mut\xe1" }
//         else { b"Muta" };
//     driver.scan_pool(tag, "_KMUTANT", |pool_addr, header, data_addr| {
//         let chunk_size = (header[2] as u64) * 16u64;
//
//         let kmutant_size = driver.pdb_store.get_offset_r("_KMUTANT.struct_size")?;
//
//         let kmutant_valid_start = data_addr;
//         let kmutant_valid_end = (pool_addr.clone() + chunk_size) - kmutant_size;
//         let mut try_kmutant_ptr = kmutant_valid_start.clone();
//
//         while try_kmutant_ptr <= kmutant_valid_end {
//             // TODO: Stronger constrain
//             let kthread_ptr = driver.address_of(&try_kmutant_ptr, "_KMUTANT.OwnerThread")?;
//             if kthread_ptr > start.address() && kthread_ptr < end.address() {
//                 break;
//             }
//             try_kmutant_ptr += 0x4;        // search exhaustively
//         }
//         if try_kmutant_ptr > kmutant_valid_end {
//             return Ok(false);
//         }
//
//         let kmutant_ptr = try_kmutant_ptr;
//         let ethread_ptr = Address::from_base(driver.address_of(&kmutant_ptr, "_KMUTANT.OwnerThread")?);
//
//         let pid: u64 = driver.decompose(&ethread_ptr, "_ETHREAD.Cid.UniqueProcess")?;
//         let tid: u64 = driver.decompose(&ethread_ptr, "_ETHREAD.Cid.UniqueThread")?;
//         let unicode_str_ptr: u64 = driver.address_of(&ethread_ptr, "_ETHREAD.ThreadName")?;
//
//         let thread_name =
//             if let Ok(name) = driver.get_unicode_string(unicode_str_ptr) {
//                 name
//             }
//             else {
//                 "".to_string()
//             };
//
//         result.push(json!({
//             "pool": format!("0x{:x}", pool_addr.address()),
//             "address": format!("0x{:x}", ethread_ptr.address()),
//             "type": "_KMUTANT",
//             "pid": pid,
//             "tid": tid,
//             "name": thread_name
//         }));
//         Ok(true)
//     })?;
//
//     Ok(result)
// }

pub fn scan_driver(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let tag = if driver.use_old_tag() {
        b"Dri\xf6"
    } else {
        b"Driv"
    };
    driver.scan_pool(tag, "_DRIVER_OBJECT", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let dob_size = driver
            .pdb_store
            .get_offset_r("_DRIVER_OBJECT.struct_size")?;
        let valid_end = (pool_addr.clone() + chunk_size) - dob_size;
        let mut try_ptr = data_addr;

        while try_ptr <= valid_end {
            // No documentation on type constrain
            let size: u16 = driver.decompose(&try_ptr, "_DRIVER_OBJECT.Size")?;
            if (size as u64) == dob_size {
                break;
            }
            try_ptr += 0x4; // search exhaustively
        }
        if try_ptr > valid_end {
            return Ok(false);
        }
        result.push(make_driver(driver, &try_ptr)?);
        Ok(true)
    })?;

    Ok(result)
}

pub fn scan_kernel_module(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    driver.scan_pool(
        b"MmLd",
        "_LDR_DATA_TABLE_ENTRY",
        |_pool_addr, _, data_addr| {
            // By reversing, this structure does not have any header
            result.push(make_ldr(driver, &data_addr)?);
            Ok(true)
        },
    )?;

    Ok(result)
}

pub fn traverse_loadedmodulelist(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let ntosbase = driver.get_kernel_base();
    let module_list_head = ntosbase + driver.pdb_store.get_offset_r("PsLoadedModuleList")?;

    let result = make_list_entry(
        driver,
        module_list_head.clone(),
        "_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks",
    )?
    .iter()
    .map(|x| make_ldr(driver, &x).unwrap_or(json!({})))
    .collect();

    Ok(result)
}

// dx Debugger.Utility.Collections.FromListEntry( *(nt!_LIST_ENTRY*)&(nt!PsActiveProcessHead), "nt!_EPROCESS", "ActiveProcessLinks")
pub fn traverse_activehead(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let ntosbase = driver.get_kernel_base();
    let process_list_head = ntosbase + driver.pdb_store.get_offset_r("PsActiveProcessHead")?;
    let eprocess_listentry_offset = driver
        .pdb_store
        .get_offset_r("_EPROCESS.ActiveProcessLinks")?;

    // TODO: make_list_entry
    let mut ptr: u64 = driver.decompose(&process_list_head, "_LIST_ENTRY.Flink")?;
    while ptr != process_list_head.address() {
        let eprocess_ptr = Address::from_base(ptr - eprocess_listentry_offset);
        result.push(make_eprocess(driver, &eprocess_ptr)?);
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
    let eprocess_listentry_offset = driver
        .pdb_store
        .get_offset_r("_KPROCESS.ProcessListEntry")?;

    // TODO: make_list_entry
    let mut ptr: u64 = driver.decompose(&process_list_head, "_LIST_ENTRY.Flink")?;
    while ptr != process_list_head.address() {
        let eprocess_ptr = Address::from_base(ptr - eprocess_listentry_offset);
        result.push(make_eprocess(driver, &eprocess_ptr)?);

        ptr = driver.decompose(&eprocess_ptr, "_KPROCESS.ProcessListEntry.Flink")?;
    }

    Ok(result)
}

// dx Debugger.Utility.Collections.FromListEntry(*(nt!_LIST_ENTRY*)&nt!HandleTableListHead, "nt!_HANDLE_TABLE", "HandleTableList").Where(h => h.QuotaProcess != 0).Select( qp => new {Process= qp.QuotaProcess} )
pub fn traverse_handletable(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();

    let ntosbase = driver.get_kernel_base();
    let process_list_head = ntosbase + driver.pdb_store.get_offset_r("HandleTableListHead")?;
    let handle_list_offset = driver
        .pdb_store
        .get_offset_r("_HANDLE_TABLE.HandleTableList")?;

    let mut ptr: u64 = driver.decompose(&process_list_head, "_LIST_ENTRY.Flink")?;
    while ptr != process_list_head.address() {
        let handle_ptr = Address::from_base(ptr - handle_list_offset);
        let quota_process: u64 = driver.decompose(&handle_ptr, "_HANDLE_TABLE.QuotaProcess")?;

        if quota_process != 0 {
            let eprocess_ptr = Address::from_base(quota_process);
            result.push(make_eprocess(driver, &eprocess_ptr)?);
        }

        ptr = driver.decompose(&handle_ptr, "_HANDLE_TABLE.HandleTableList.Flink")?;
    }

    Ok(result)
}

pub fn traverse_unloadeddrivers(driver: &DriverState) -> BoxResult<Vec<Value>> {
    let mut result: Vec<Value> = Vec::new();
    let ntosbase = driver.get_kernel_base();
    let unload_array_ptr = ntosbase.clone() + driver.pdb_store.get_offset_r("MmUnloadedDrivers")?;
    let num_unload_ptr =
        ntosbase.clone() + driver.pdb_store.get_offset_r("MmLastUnloadedDriver")?;

    let unload_array = driver.deref_addr_new::<u64>(unload_array_ptr.address());
    if unload_array == 0 {
        return Err("The unload driver list pointer is null".into());
    }

    // by reversing MmLocateUnloadedDriver
    let num_unload = driver.deref_addr_new::<u32>(num_unload_ptr.address()) as u64;
    let bound = if num_unload > 0x32 { 0x32 } else { num_unload };
    let drivers = (0..bound).map(|i| Address::from_base(unload_array + (i * 0x28)));

    for driver_addr in drivers {
        let name = driver
            .get_unicode_string(driver_addr.address())
            .unwrap_or("".to_string());
        let start_addr: u64 = driver.decompose(&driver_addr, "_UNLOADED_DRIVERS.StartAddress")?;
        let end_addr: u64 = driver.decompose(&driver_addr, "_UNLOADED_DRIVERS.EndAddress")?;
        let current_time: u64 = driver.decompose(&driver_addr, "_UNLOADED_DRIVERS.CurrentTime")?;
        let time = to_epoch(current_time);

        result.push(json!({
            "address": format!("0x{:x}", driver_addr.address()),
            "type": "_UNLOADED_DRIVERS",
            "name": name,
            "start_addr": format!("0x{:x}", start_addr),
            "end_addr": format!("0x{:x}", end_addr),
            "time_unix": time.timestamp(),
            "time_rfc2822": time.to_rfc2822()
        }));
    }

    Ok(result)
}

pub fn ssdt_table(driver: &DriverState) -> BoxResult<Vec<u64>> {
    // https://github.com/volatilityfoundation/volatility3/blob/master/volatility/framework/plugins/windows/ssdt.py
    let ntosbase = driver.get_kernel_base();
    let servicetable = ntosbase.clone() + driver.pdb_store.get_offset_r("KiServiceTable")?;
    let servicelimit_ptr = ntosbase.clone() + driver.pdb_store.get_offset_r("KiServiceLimit")?;

    let servicelimit = driver.deref_addr_new::<u32>(servicelimit_ptr.address()) as u64;
    let ssdt: Vec<u64> = driver
        .deref_array::<i32>(&servicetable, servicelimit)
        .iter()
        .map(|entry| {
            // the entry can be negative, we need to do calculation using signed int
            // and convert back to unsigned int for address
            ((servicetable.address() as i64) + ((*entry >> 4) as i64)) as u64
        })
        .collect();
    Ok(ssdt)
}

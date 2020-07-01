use std::error::Error;
use std::str::{from_utf8};
use serde_json::{json, Value};
use crate::driver_state::DriverState;
use crate::address::Address;
use crate::{get_device_type, to_epoch};

type BoxResult<T> = Result<T, Box<dyn Error>>;

pub fn make_list_entry(d: &DriverState, a: Address, next: &str) -> BoxResult<Vec<Address>> {
    // `a` is the address to the _LIST_ENTRY
    // `next` is the _LIST_ENTRY field in the object
    // return a list of address for object
    let mut result: Vec<Address> = Vec::new();
    let list_offset = d.pdb_store.get_offset_r(next)?;

    let mut ptr: u64 = d.deref_addr_new(a.address());
    while ptr != a.address() {
        let obj_ptr = Address::from_base(ptr - list_offset);
        ptr = d.decompose(&obj_ptr, &format!("{}.Flink", next))?;
        result.push(obj_ptr);
    }
    Ok(result)
}

pub fn make_eprocess(d: &DriverState, a: &Address) -> BoxResult<Value> {
    let createtime: u64 = d.decompose(a, "_EPROCESS.CreateTime")?;
    let exittime: u64 = d.decompose(a, "_EPROCESS.ExitTime")?;
    let pid: u64 = d.decompose(a, "_EPROCESS.UniqueProcessId")?;
    let ppid: u64 = d.decompose(a, "_EPROCESS.InheritedFromUniqueProcessId")?;
    let image_name: Vec<u8> = d.decompose_array(a, "_EPROCESS.ImageFileName", 15)?;
    let filename_ptr = d.address_of(a, "_EPROCESS.ImageFilePointer.FileName")
                        .unwrap_or(0); // ImageFilePointer is after Windows 10 Anniversary

    let eprocess_name =
        if let Ok(name) = from_utf8(&image_name) {
            name.to_string().trim_end_matches(char::from(0)).to_string()
        } else {
            "".to_string()
        };
    let binary_path = d.get_unicode_string(filename_ptr)
                       .unwrap_or("".to_string());

    let thread_head = d.address_of(a, "_EPROCESS.ThreadListHead")?;
    let threads: Vec<Value> =
        make_list_entry(d, Address::from_base(thread_head), "_ETHREAD.ThreadListEntry")
        .unwrap_or(Vec::new()).iter()
        .map(|thread_addr| {
            make_ethread(d, thread_addr)
            .unwrap_or(json!({})) // unlikely
        }).collect();

    let c_t = to_epoch(createtime);
    let e_t = to_epoch(exittime);

    Ok(json!({
        "address": format!("0x{:x}", a.address()),
        "type": "_EPROCESS",
        "pid": pid,
        "ppid": ppid,
        "name": eprocess_name,
        "path": binary_path,
        "threads": threads,
        "createtime": {
            "unix": c_t.timestamp(),
            "rfc2822": c_t.to_rfc2822()
        },
        "exittime": {
            "unix": e_t.timestamp(),
            "rfc2822": e_t.to_rfc2822(),
        }
    }))
}

pub fn make_ethread(d: &DriverState, a: &Address) -> BoxResult<Value> {
    // let createtime: u64 = d.decompose(a, "_ETHREAD.CreateTime")?;
    // let exittime: u64 = d.decompose(a, "_ETHREAD.ExitTime")?;
    let pid: u64 = d.decompose(a, "_ETHREAD.Cid.UniqueProcess")?;
    let tid: u64 = d.decompose(a, "_ETHREAD.Cid.UniqueThread")?;
    let name_ptr: u64 = d.address_of(a, "_ETHREAD.ThreadName")
                        .unwrap_or(0); // ThreadName is after Windows 10 Anniversary

    let thread_name =
        if let Ok(name) = d.get_unicode_string(name_ptr) { name }
        else { "".to_string() };

    // let c_t = to_epoch(createtime);
    // let e_t = to_epoch(exittime);

    Ok(json!({
        "address": format!("0x{:x}", a.address()),
        "type": "_ETHREAD",
        "tid": tid,
        "pid": pid,
        "name": thread_name,
        // "createtime": {
        //     "unix": c_t.timestamp(),
        //     "rfc2822": c_t.to_rfc2822()
        // },
        // "exittime": {
        //     "unix": e_t.timestamp(),
        //     "rfc2822": e_t.to_rfc2822(),
        // }
    }))
}

pub fn make_driver(d: &DriverState, a: &Address) -> BoxResult<Value> {
    let devicename_ptr = d.address_of(a, "_DRIVER_OBJECT.DriverName")?;
    let servicekey_ptr = d.address_of(a, "_DRIVER_OBJECT.DriverExtension.ServiceKeyName")?;
    let hardware_ptr: u64 = d.decompose(a, "_DRIVER_OBJECT.HardwareDatabase")?;
    let major_function: Vec<u64> = d.decompose_array(a, "_DRIVER_OBJECT.MajorFunction", 28)?;
    let start: u64 = d.decompose(a, "_DRIVER_OBJECT.DriverStart")?;
    let init: u64 = d.decompose(a, "_DRIVER_OBJECT.DriverInit")?;
    let unload: u64 = d.decompose(a, "_DRIVER_OBJECT.DriverUnload")?;
    let size: u64 = d.decompose(a, "_DRIVER_OBJECT.DriverSize")?;

    let devicename = d.get_unicode_string(devicename_ptr)
                        .unwrap_or("".to_string());
    let hardware = d.get_unicode_string(hardware_ptr)
                    .unwrap_or("".to_string());
    let servicekey = d.get_unicode_string(servicekey_ptr)
                        .unwrap_or("".to_string());

    // device tree walk
    let devices = {
        let mut driver_devices: Vec<Value> = Vec::new();
        let mut device_ptr: u64 = d.decompose(a, "_DRIVER_OBJECT.DeviceObject")?;
        while device_ptr != 0 {
            let addr = Address::from_base(device_ptr);
            let device_type: u32 = d.decompose(&addr, "_DEVICE_OBJECT.DeviceType")?;

            // get attached devices
            let mut attached_ptr: u64 = d.decompose(&addr, "_DEVICE_OBJECT.AttachedDevice")?;
            let mut attached_devices: Vec<Value> = Vec::new();
            while attached_ptr != 0 {
                let attached = Address::from_base(attached_ptr);
                let attached_device_type: u32 = d.decompose(&attached, "_DEVICE_OBJECT.DeviceType")?;
                attached_devices.push(json!({
                    "address": format!("0x{:x}", attached_ptr),
                    "type": "_DEVICE_OBJECT",
                    "devicetype": get_device_type(attached_device_type)
                }));
                attached_ptr = d.decompose(&attached, "_DEVICE_OBJECT.AttachedDevice")?;
            }
            driver_devices.push(json!({
                "address": format!("0x{:x}", device_ptr),
                "type": "_DEVICE_OBJECT",
                "devicetype": get_device_type(device_type),
                "attached": attached_devices
            }));
            device_ptr = d.decompose(&addr, "_DEVICE_OBJECT.NextDevice")?;
        }
        driver_devices
    };

    Ok(json!({
        "address": format!("0x{:x}", a.address()),
        "type": "_DRIVER_OBJECT",
        "device": devicename,
        "hardware": hardware,
        "major_function": major_function.into_iter()
                            .map(|func| format!("0x{:x}", func))
                            .collect::<Vec<String>>(),
        "servicekey": servicekey,
        "start": format!("0x{:x}", start),
        "init": format!("0x{:x}", init),
        "unload": format!("0x{:x}", unload),
        "size": format!("0x{:x}", size),
        "devicetree": devices
    }))
}

pub fn make_ldr(d: &DriverState, a: &Address) -> BoxResult<Value> {
    let dllbase: u64 = d.decompose(a, "_LDR_DATA_TABLE_ENTRY.DllBase")?;
    let entry: u64 = d.decompose(a, "_LDR_DATA_TABLE_ENTRY.EntryPoint")?;
    let size: u64 = d.decompose(a, "_LDR_DATA_TABLE_ENTRY.SizeOfImage")?;
    let fullname_ptr = d.address_of(a, "_LDR_DATA_TABLE_ENTRY.FullDllName")?;
    let basename_ptr = d.address_of(a, "_LDR_DATA_TABLE_ENTRY.BaseDllName")?;

    let fullname = d.get_unicode_string(fullname_ptr)
                    .unwrap_or("".to_string());
    let basename = d.get_unicode_string(basename_ptr)
                    .unwrap_or("".to_string());

    let ldr_load: Vec<String> =
        make_list_entry(d, a.clone(), "_LDR_DATA_TABLE_ENTRY.InLoadOrderLinks")?
        .iter().map(|x| format!("0x{:x}", x.address())).collect();
    let ldr_mem: Vec<String> =
        make_list_entry(d, a.clone(), "_LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks")?
        .iter().map(|x| format!("0x{:x}", x.address())).collect();
    let ldr_init: Vec<String> =
        make_list_entry(d, a.clone(), "_LDR_DATA_TABLE_ENTRY.InInitializationOrderLinks")?
        .iter().map(|x| format!("0x{:x}", x.address())).collect();

    Ok(json!({
        "address": format!("0x{:x}", a.address()),
        "type": "_LDR_DATA_TABLE_ENTRY",
        "dllbase": format!("0x{:x}", dllbase),
        "entry": format!("0x{:x}", entry),
        "size": format!("0x{:x}", size),
        "FullName": fullname,
        "BaseName": basename,
        "ldr_load": ldr_load,
        "ldr_mem": ldr_mem,
        "ldr_init": ldr_init
    }))
}

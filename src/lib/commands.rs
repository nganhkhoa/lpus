use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;

use prettytable::{cell, row, Table};

use parse_int::parse;

use crate::{
    driver_state::DriverState, scan_driver, scan_eprocess, scan_ethread, scan_kernel_module,
    ssdt_table, traverse_activehead, traverse_handletable, traverse_kiprocesslist,
    traverse_loadedmodulelist, traverse_unloadeddrivers,
};

pub fn ssdt(driver: &DriverState, only_hooked: bool) {
    let loaded = traverse_loadedmodulelist(&driver).unwrap_or(Vec::new());
    let ssdt = ssdt_table(&driver).unwrap_or(Vec::new());
    let ntosbase = driver.get_kernel_base();

    for (idx, func) in ssdt.iter().enumerate() {
        let owner = loaded.iter().find_map(|r| {
            let base = r["dllbase"]
                .as_str()
                .and_then(|b| parse::<u64>(b).ok())
                .unwrap_or(0);
            let size = r["size"]
                .as_str()
                .and_then(|s| parse::<u64>(s).ok())
                .unwrap_or(0);

            if *func > base && *func < base + size {
                let module = r["BaseName"].as_str().unwrap();
                Some(module)
            } else {
                None
            }
        });
        if owner == Some("ntoskrnl.exe") {
            if !only_hooked {
                let offset = func - ntosbase.address();
                let funcname: String = {
                    driver
                        .pdb_store
                        .symbols
                        .iter()
                        .find_map(|(name, o)| {
                            if o.clone() == offset {
                                Some(name.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or("(??)".to_string())
                };
                println!("SSDT [{}]\t0x{:x}", idx, func);
                println!("\towned by nt!{}", funcname);
            }
        } else if let Some(owner_) = owner {
            println!("SSDT [{}]\t0x{:x}", idx, func);
            println!("\\thooked by {}", owner_);
        } else {
            println!("SSDT [{}]\t0x{:x}", idx, func);
            println!("\tmissing owner");
        }
    }
}

pub fn psxview(driver: &DriverState) {
    fn process_in_list(addr: &str, list: &Vec<Value>) -> bool {
        for r in list.iter() {
            if r["address"].as_str().unwrap() == addr {
                return true;
            }
        }
        false
    }

    fn get_from_list(addr: &str, list: &Vec<Value>) -> Option<Value> {
        for r in list.iter() {
            if r["address"].as_str().unwrap() == addr {
                return Some(r.clone());
            }
        }
        None
    }

    fn process_in_list_thread(addr: &str, list: &Vec<Value>) -> bool {
        for r in list.iter() {
            if r["eprocess"].as_str().unwrap() == addr {
                return true;
            }
        }
        false
    }

    let process_scan = scan_eprocess(&driver).unwrap_or(Vec::new());
    let thread_scan = scan_ethread(&driver).unwrap_or(Vec::new());
    let activehead = traverse_activehead(&driver).unwrap_or(Vec::new());
    let kiprocesslist = traverse_kiprocesslist(&driver).unwrap_or(Vec::new());
    let handletable = traverse_handletable(&driver).unwrap_or(Vec::new());

    let mut unique_process = HashSet::new();
    for list in [&process_scan, &activehead, &kiprocesslist, &handletable].iter() {
        for r in list.iter() {
            let addr = r["address"].as_str().unwrap();
            unique_process.insert(addr);
        }
    }

    let mut table = Table::new();
    table.add_row(row![
        "Address",
        "Name",
        "pid",
        "ppid",
        "PoolTagScan",
        "ActiveProcessHead",
        "KiProcessListHead",
        "HandleTableList",
        "ThreadScan"
    ]);
    for p in &unique_process {
        let addr = p.to_string();
        let v = {
            if let Some(vv) = get_from_list(&addr, &activehead) {
                vv
            } else {
                get_from_list(&addr, &process_scan).unwrap_or_default()
            }
        };
        table.add_row(row![
            &addr,
            v["name"].as_str().unwrap_or("(??)"),
            v["pid"].as_i64().unwrap_or(-1),
            v["ppid"].as_i64().unwrap_or(-1),
            process_in_list(&addr, &process_scan),
            process_in_list(&addr, &activehead),
            process_in_list(&addr, &kiprocesslist),
            process_in_list(&addr, &handletable),
            process_in_list_thread(&addr, &thread_scan)
        ]);
    }

    table.printstd();
}
pub fn modscan(driver: &DriverState) {
    let dd = scan_kernel_module(&driver).unwrap_or(Vec::new());
    let mut table = Table::new();
    table.add_row(row!["Address", "Base name", "Base", "Size", "File"]);
    for d in &dd {
        table.add_row(row![
            d["address"].as_str().unwrap_or("(??)"),
            d["BaseName"].as_str().unwrap_or("(??)"),
            d["dllbase"].as_str().unwrap_or("(??)"),
            d["size"].as_str().unwrap_or("(??)"),
            d["FullName"].as_str().unwrap_or("(??)"),
        ]);
    }
    table.printstd();
}
pub fn driverscan(driver: &DriverState) {
    let dd = scan_driver(&driver).unwrap_or(Vec::new());
    let mut table = Table::new();
    table.add_row(row!["Address", "Device", "Service key", "Start", "Size"]);
    for d in &dd {
        table.add_row(row![
            d["address"].as_str().unwrap_or("(??)"),
            d["device"].as_str().unwrap_or("(??)"),
            d["servicekey"].as_str().unwrap_or("(??)"),
            d["start"].as_str().unwrap_or("(??)"),
            d["size"].as_str().unwrap_or("(??)"),
        ]);
    }
    table.printstd();
}
pub fn unloadedmodules(driver: &DriverState) {
    let modules = traverse_unloadeddrivers(&driver).unwrap_or(Vec::new());
    let mut table = Table::new();
    table.add_row(row!["Address", "Driver", "Start", "End", "Time"]);
    for m in &modules {
        table.add_row(row![
            m["address"].as_str().unwrap_or("(??)"),
            m["name"].as_str().unwrap_or("(??)"),
            m["start_addr"].as_str().unwrap_or("(??)"),
            m["end_addr"].as_str().unwrap_or("(??)"),
            m["time_rfc2822"].as_str().unwrap_or("(??)"),
        ]);
    }
    table.printstd();
}

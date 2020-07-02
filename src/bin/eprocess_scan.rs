use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;

#[macro_use]
extern crate prettytable;
use prettytable::Table;

use lpus::{
    driver_state::DriverState, scan_eprocess, scan_ethread, traverse_activehead,
    traverse_handletable, traverse_kiprocesslist,
};

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

// fn get_process_from_list(addr: String, list: &Vec<Value>) -> String { }

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!(
            "Windows version {:?} is not supported",
            driver.windows_ffi.short_version
        )
        .into());
    }
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

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
        let v = get_from_list(&addr, &activehead).unwrap_or_default();
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

    // for r in process_scan.iter() {
    //     println!("{:#}", r.to_string());
    // }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

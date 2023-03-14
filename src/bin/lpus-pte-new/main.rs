use clap::{App, Arg};
use lpus::{driver_state::DriverState, find_eprocess_by_name};
use lpus::pte_scan::*;
use std::error::Error;

fn main()-> Result<(), Box<dyn Error>> {
    let matches = App::new("Listing all PTEs")
    .arg(
        Arg::with_name("name")
            .long("name")
            .short("n")
            .multiple(false)
            .help("Specify the names of the processes")
            .takes_value(true)
            .required(true),
    )   
        .get_matches();

    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!(
            "Windows version {:?} is not supported",
            driver.windows_ffi.short_version
        )
            .into());
    }
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    if matches.is_present("name"){
        let name = matches.value_of("name").unwrap().to_string();
        // Running pool tag scan
        println!("[*] Running pool tag scan");
        let proc_list = find_eprocess_by_name(&driver, &name, true).unwrap_or(Vec::new());
        if proc_list.len() == 0 {
            return Err(format!("No process with name {}", name).into());
        } else if proc_list.len() > 1 {
            return Err(format!("Many processes with name {}", name).into())
        }

        let cr3 = proc_list[0]["directory_table"].as_u64().unwrap();   
        let page_list = scan_rwx_pages(&driver, cr3).unwrap();

        for pte in page_list {
            println!("R+W page address: 0x{:x}", pte.get_pfn(&driver).unwrap() << 12);
        }
    }
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}
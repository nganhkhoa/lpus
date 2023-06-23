use clap::{App, Arg};
use lpus::{driver_state::DriverState, find_eprocess_by_name, find_eprocess_by_pid, scan_eprocess, address::Address};
use lpus::utils::hex_dump::print_hex_dump;
use lpus::utils::disassemble::disassemble_array_x64;
use lpus::pte_scan::*;
use std::error::Error;

const PAGE_SIZE: u64 = 0x1000;

fn main()-> Result<(), Box<dyn Error>> {
    let matches = App::new("Listing all PTEs")
    .arg(
        Arg::with_name("name")
            .long("name")
            .short("n")
            .multiple(false)
            .help("Specify the name of the processes")
            .takes_value(true)
            .required(false),
    )   
    .arg(
        Arg::with_name("pid")
        .long("pid")
        .short("p")
        .multiple(false)
        .help("Specify the pid of the process")
        .takes_value(true)
        .required(false)

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
    let mut proc_list: Vec<_>;

    // Running pool tag scan
    println!("[*] Running pool tag scan");
    if matches.is_present("pid") {
        let pid: u64 = matches.value_of("pid").unwrap().to_string().parse().unwrap();    
        proc_list = find_eprocess_by_pid(&driver, pid).unwrap_or(Vec::new());

    } else if matches.is_present("name"){
        let name = matches.value_of("name").unwrap().to_string();
        proc_list = find_eprocess_by_name(&driver, &name, false).unwrap_or(Vec::new());
        
        if proc_list.len() == 0 {
            return Err(format!("No process with name {}", name).into());
        }

    } else {
        // Default to scan first 100 processes
        // Filter our tool our of the target list
        // proc_list = scan_eprocess(&driver).unwrap_or(Vec::new());
        let full_proc_list = scan_eprocess(&driver).unwrap_or(Vec::new());
        proc_list = full_proc_list[0..100].into();
        // println!("[*] Scanning {:?} out of total {:?} processes for injected code", proc_list.len(), full_proc_list.len());
        println!("[*] Scanning {:?} processes for injected code.", proc_list.len());
    }
        
    for (index, proc) in proc_list.iter().enumerate() {
        let cr3 = proc["directory_table"].as_u64().unwrap();   
	// println!("\n====== Scanning process: {} - PID: {} - No {} ======\n", proc["name"], proc["pid"], index);
        let page_list = scan_injected_pages(&driver, cr3).unwrap();
        if page_list.len() != 0 {
	    println!("\n====== {} injected pages in process: {} - PID: {} ======\n", page_list.len(), proc["name"], proc["pid"]);
            println!("Detected {:?} injected pages", page_list.len());
            for pte in &page_list[0..1] {
                let physical_addr = pte.get_pfn(&driver).unwrap() << 12;
                println!("Injected code at: 0x{:x}", physical_addr);
                let content: Vec<u8> = driver.deref_array_physical(&Address::from_base(physical_addr), PAGE_SIZE);
                print_hex_dump(&content, physical_addr);
                println!("---------------- Disassemble ----------------");
                disassemble_array_x64(&content, physical_addr);
                println!("\n***************************************************************\n");
            }
        }
    }
        
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}
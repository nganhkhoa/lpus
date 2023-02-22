use clap::{App, Arg};
use lpus::{driver_state::DriverState, scan_eprocess};
use lpus::paging_structs::*;
use lpus::paging_traverse::*;
use std::error::Error;

fn main()-> Result<(), Box<dyn Error>> {
    let matches = App::new("Translate virtual address")
    .arg(
        Arg::with_name("name")
            .long("name")
            .short("n")
            .multiple(false)
            .help("Specify the names of the processes to display")
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
        let name = matches.value_of("name").unwrap();
        println!("[*] Finding image base of process {:?} in physical address", name);

        // Running pool tag scan
        println!("[*] Running pool tag scan");
        let mut proc_list = scan_eprocess(&driver).unwrap_or(Vec::new());
        proc_list = proc_list
            .into_iter()
            .filter(|proc|proc["name"].as_str().unwrap() == name)
            .collect();

        assert!(proc_list.len() == 1, "There are many process with the same name");

        let cr3 = proc_list[0]["directory_table"].as_u64().unwrap();
		
		// Get image base address
        println!("[*] Cr3: 0x{:x}", cr3);
        let pte_table = list_all_pte(&driver, cr3);
    }
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}
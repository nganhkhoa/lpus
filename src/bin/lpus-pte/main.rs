use clap::{App, Arg};
use lpus::{driver_state::DriverState, scan_eprocess};
use lpus::paging_traverse::*;
use lpus::paging_structs::*;
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
        let name = matches.value_of("name").unwrap();
        // Running pool tag scan
        println!("[*] Running pool tag scan");
        let mut proc_list = scan_eprocess(&driver).unwrap_or(Vec::new());
        proc_list = proc_list
            .into_iter()
            .filter(|proc|proc["name"].as_str().unwrap() == name)
            .collect();

        assert!(proc_list.len() == 1, "There are many processes with the same name");

        let cr3 = proc_list[0]["directory_table"].as_u64().unwrap();
		
		// Get image base address
        println!("[*] Cr3: 0x{:x}", cr3);
        let pte_table = list_all_pte(&driver, cr3);

        for pte in pte_table {
            if pte.get_state() == PageState::HARDWARE {
                let hardware_pte = pte.as_any().downcast_ref::<MMPTE_HARDWARE>().unwrap();
                if hardware_pte.is_executable() && hardware_pte.Write.value() != 0 {
                    println!("PFN of write+exec page: 0x{:x}", pte.get_pfn());
                }
                
            } /*else {
                println!("Invalid PML4E: {:?}", pte);
            }*/
        }
    }
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}
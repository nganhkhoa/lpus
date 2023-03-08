use clap::{App, Arg, SubCommand};
use lpus::{driver_state::DriverState, scan_eprocess, address};
use std::error::Error;
use std::io::{self, Write};
use lpus::address::Address;

fn is_valid_entry(entry: u64) -> bool {
    /*
    Check if an entry in the paging structure is valid
    All entries in the paging structure (PML4, PDPT, Page directory, Page table) have a `valid` bit (bit 0)
    We can use that to check if an entry is valid or not
    Also an entry with no content is also considered invalid
     */
    return (entry != 0) && (entry & 1 == 1);
}

fn get_cr3(driver_state: &DriverState, pid: u64) -> Result<u64, Box<dyn Error>>{
    /*
    Read the cr3 register, aka Directory table base address of the specified process
    The register is read by first using lpus pool tag scanning api to scan for a suitable _EPROCESS object
    Then read the `directory_table` field in the found structure.
     */

    let mut proc_list = scan_eprocess(&driver_state).unwrap_or(Vec::new());
    proc_list = proc_list
        .into_iter()
        .filter(|i| i["pid"].as_u64().unwrap() == pid)
        .collect();

    //Pid is unique for each process, so this is just to make sure
    println!("Pid: {}, Proc list: {}", pid, proc_list.len());
    assert!(proc_list.len() == 1);

    return Ok(proc_list[0]["directory_table"].as_u64().unwrap())

}

fn get_pml4e(driver_state: &DriverState, cr3: u64, vaddr: u64) -> Result<u64, Box<dyn Error>> {
    /*
    Returns the content of the Page Map Level 4 (PML4) entry for the virtual address
    # Arguments
        * driver_state: DriverState object
        * cr3: value of cr3 register (or Directory table base address) from process
        * vaadr: virtual address that needs translating

    Intel spec for PML4e (from Volatility) address:
        "Bits 51:12 are from CR3" [Intel]
        "Bits 11:3 are bits 47:39 of the linear address" [Intel]
        "Bits 2:0 are 0" [Intel]
     */
    let pml4e_addr = (cr3 & 0xffffffffff000) | ((vaddr & 0xff8000000000) >> 36);
    let pml4e_content: u64 = driver_state.deref_physical_addr(pml4e_addr);

    if !is_valid_entry(pml4e_content) {
        return Err(format!("Pml4e of address 0x{:x}: 0x{:x} is not valid", vaddr, pml4e_content).into());
    }
    Ok(pml4e_content)
}

fn get_pdpte(driver_state: &DriverState, pml4e: u64, vaddr: u64) -> Result<u64, Box<dyn Error>> {
    /*
    Returns the content of the Page Directory Pointer entry for the virtual address
    # Arguments
        * driver_state: DriverState object
        * pml4e: Content of the Page Map Level 4 entry of the virtual address
        * vaadr: virtual address that needs translating

    Intel spec for Page Directory Pointer entry address:
        "Bits 51:12 are from the PML4E" [Intel]
        "Bits 11:3 are bits 38:30 of the linear address" [Intel]
        "Bits 2:0 are all 0" [Intel]
     */
    let pdpte_paddr = (pml4e & 0xffffffffff000) | ((vaddr & 0x7FC0000000) >> 27);
    let pdpte_content: u64 = driver_state.deref_physical_addr(pdpte_paddr);

    if !is_valid_entry(pdpte_content) {
        return Err(format!("PDPTE of address 0x{:x}: 0x{:x} is not valid", vaddr, pdpte_content).into());
    }

    Ok(pdpte_content)
}

fn get_pde(driver_state:&DriverState, pdpte: u64, vaddr: u64) -> Result<u64, Box<dyn Error>> {
    /*
    Return the content of the Page Directory entry for the virtual address
     */
    let pde_addr = (pdpte & 0xFFFFFFFFFF000) | ((vaddr & 0x3fe00000) >> 18);
    let pde_content: u64 = driver_state.deref_physical_addr(pde_addr);
    if !is_valid_entry(pde_content) {
        return Err(format!("PDE of address 0x{:x} is not valid", vaddr).into());
    }
    Ok(pde_content)
}

fn get_pte(driver_state: &DriverState, pde: u64, vaddr: u64) -> Result<u64, Box<dyn Error>> {
    /*
    Return the content of the Page Table Entry for the virtual address
     */
    let pte_addr = (pde & 0xFFFFFFFFFF000) | ((vaddr & 0x1ff000) >> 9);
    let pte_content: u64 = driver_state.deref_physical_addr(pte_addr);
    if !is_valid_entry(pte_content) {
        return Err(format!("PTE of address 0x{:x} is not valid", vaddr).into());
    }
    Ok(pte_content)

}

fn translate_addr(driver_state: &DriverState, cr3:u64, vaddr: u64, debug: bool) -> Result<u64, Box<dyn Error>> {
    /*
    Returns the physical address of the Page Map Level 4 (PML4) entry for the virtual address
    # Arguments
        * cr3: process cr3
        * vaadr: virtual address that needs translating
     */

    //Only handle 4KB paging at the moment
    if (debug) {
        println!("\tCR3: 0x{:x}", cr3);
    }

    let pml4e: u64 = get_pml4e(driver_state, cr3, vaddr).unwrap();
    if (debug) {
        println!("\tPML4e: 0x{:x}", pml4e);
    }
    //return Ok(pml4e);

    let pdpte: u64 = get_pdpte(driver_state, pml4e, vaddr).unwrap();
    if (debug) {
        println!("\tPDPTE: 0x{:x}", pdpte);
    }
    
    let pde: u64 = get_pde(driver_state, pdpte, vaddr).unwrap();
    if (debug) {
        println!("\tPDE: 0x{:x}", pde);
    }

    let pte: u64 = get_pte(driver_state, pde, vaddr).unwrap();
    if (debug) {
        println!("\tPTE: 0x{:x}", pte);
    }
    
    //Convert virtual address to physical address
    let pfn: u64 = pte & 0xFFFFFFFFFF000;
    let offset: u64 = vaddr & ((1 << 12) - 1);
    let paddr: u64 = pfn | offset;

    Ok(paddr)
}

fn getImageBase(driver_state: &DriverState, cr3: u64, eprocess_addr: u64) -> Result<u64, Box<dyn Error>> {

    // Query data from peb by physical address because i have no way to get to process's context
    let addr: Address = Address::from_base(eprocess_addr);
    let ppeb = driver_state.decompose(&addr, "_EPROCESS.Peb")?;
    let ppeb_addr : Address = Address::from_base(ppeb);
    let image_base_ptr: u64 = driver_state.address_of(&ppeb_addr, "_PEB.ImageBaseAddress")?;

    let image_base_ptr_paddr = translate_addr(driver_state, cr3, image_base_ptr, false).unwrap();
    let image_base : u64 = driver_state.deref_physical_addr(image_base_ptr_paddr);

    Ok(image_base)

}

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
        let eprocess_addr = proc_list[0]["address_val"].as_u64().unwrap();
        println!("[*] Cr3: 0x{:x}", cr3);
        let image_base = getImageBase(&driver, cr3, eprocess_addr).unwrap();
		
        //let image_base = proc_list[0]["image_base"].as_u64().unwrap();

        println!("[*] Image base: 0x{:x}", image_base);
        println!("[*] Translating image base to physical address");
        let paddr = translate_addr(&driver, cr3, image_base, true).unwrap();
        println!("[*] Physical address of image base: 0x{:x}", paddr);
		
		let data: [u8; 16] = driver.deref_physical_addr(paddr);

		println!("[*] Sample data at image base: {:x?}", data);
    }
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}
use clap::{App, Arg};
use lpus::utils::mask_cast::MaskCast;
use lpus::{driver_state::DriverState, scan_eprocess};
use lpus::address::*;
use lpus::paging_structs::*;
use lpus::pdb_store::*;
use winapi::um::winbase::AddAtomW;
use lpus::utils::*;
use std::error::Error;
use std::mem::{size_of};


fn main()-> Result<(), Box<dyn Error>> {
    // let matches = App::new("Translate virtual address")
    // .arg(
    //     Arg::with_name("name")
    //         .long("name")
    //         .short("n")
    //         .multiple(false)
    //         .help("Specify the names of the processes to display")
    //         .takes_value(true)
    //         .required(true),
    // )   
    //     .get_matches();

    // let mut driver = DriverState::new();
    // if !driver.is_supported() {
    //     return Err(format!(
    //         "Windows version {:?} is not supported",
    //         driver.windows_ffi.short_version
    //     )
    //         .into());
    // }
    // println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    // Test new decompose
    // let ntosbase = driver.get_kernel_base();
    // let [start_address, end_address] = driver.get_nonpaged_range(&ntosbase)?;
    // let struct_name = "_EPROCESS.CreateTime";
    // let test_addr = ntosbase;

    // let a64: u64 = driver.decompose(&test_addr, struct_name).unwrap();
    // let b64: u64 = driver.decompose_new(&test_addr, struct_name).unwrap();
    // println!("64-bit test a = {}, b = {}, a == b: {}", a64, b64, a64 == b64);

    // let a32: u32 = driver.decompose(&test_addr, struct_name).unwrap();
    // let b32: u32 = driver.decompose_new(&test_addr, struct_name).unwrap();
    // println!("32-bit test a = {}, b = {}, a == b: {}", a32, b32, a32 == b32);

    // let a16: u16 = driver.decompose(&test_addr, struct_name).unwrap();
    // let b16: u16 = driver.decompose_new(&test_addr, struct_name).unwrap();
    // println!("16-bit test a = {}, b = {}, a == b: {}", a16, b16, a16 == b16);

    // let a8: u8 = driver.decompose(&test_addr, struct_name).unwrap();
    // let b8: u8 = driver.decompose_new(&test_addr, struct_name).unwrap();
    // println!("8-bit test a = {}, b = {}, a == b: {}", a8, b8, a8 == b8);


    // if matches.is_present("name"){
    //     let name = matches.value_of("name").unwrap();
    //     println!("[*] Finding image base of process {:?} in physical address", name);

    //     // Running pool tag scan
    //     println!("[*] Running pool tag scan");
    //     let mut proc_list = scan_eprocess(&driver).unwrap_or(Vec::new());
    //     proc_list = proc_list
    //         .into_iter()
    //         .filter(|proc|proc["name"].as_str().unwrap() == name)
    //         .collect();

    //     assert!(proc_list.len() == 1, "There are many process with the same name");

    //     let cr3 = proc_list[0]["directory_table"].as_u64().unwrap();
    //     println!("[*] Cr3: 0x{:x}", cr3);   

    //     let addr = (cr3 & 0xffffffffff000) | (3  << 3);
    //     let data : u64 = driver.deref_physical_addr(addr);
    //     println!("Test entry {} at address: {}", data, addr);

    //     let entry = PML4E::new(data);
    //     println!("Old way: {}", entry.pfn);

    //     let new_way : u64 = driver.decompose_physical(&Address::from_base(addr), "_HARDWARE_PTE.PageFrameNumber").unwrap();
    //     println!("New way: {}", new_way)
        
    // }
    // println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());

    let pdb = parse_pdb().unwrap();
    let addr = Address::from_base(0);
    let (addr1, mask1, len1) = pdb.decompose(&addr, "_MMPTE_HARDWARE.NoExecute").unwrap();
    let (addr2, mask2, len2) = pdb.decompose(&addr, "_MMPTE_HARDWARE.Write").unwrap();
    // println!("Addr: {}", addr);
    let a1: u8 = 0x47;
    // println!("nx: {}, w: {}", mask1(a1.mask_cast_to()), mask2(a1.mask_cast_to()));
    test(&pdb, a1);

    Ok(())
}

pub fn test<T: Default + Default + MaskCast<u64>>(pdb: &PdbStore, val :T) {
    let addr = Address::from_base(0);
    let (addr1, mask1, len1) = pdb.decompose(&addr, "_MMPTE_HARDWARE.NoExecute").unwrap();
    println!("{}", len1);
    println!("{}", size_of::<T>());

}
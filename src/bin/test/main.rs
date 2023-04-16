use clap::{App, Arg};
use lpus::utils::hex_dump::print_hex_dump;
use lpus::utils::mask_cast::MaskCast;
use lpus::{driver_state::DriverState, scan_eprocess};
use lpus::address::*;
use lpus::pdb_store::*;
use lpus::utils::*;
use std::error::Error;
use std::mem::{size_of};

fn main() -> Result<(), Box<dyn Error>> {
    // let mut driver = DriverState::new();
    // if !driver.is_supported() {
    //     return Err(format!(
    //         "Windows version {:?} is not supported",
    //         driver.windows_ffi.short_version
    //     )
    //         .into());
    // }
    // println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    // let kernel_base = driver.get_kernel_base();
    // let pfn_db_base = kernel_base + driver.pdb_store.get_offset_r("MmPfnDatabase").unwrap();
    // println!("PFNDB: 0x{:x}", pfn_db_base.address());

    // println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());

    // let pdb = parse_pdb().unwrap();
    // let u4 = pdb.get_offset("_MMPFN.u4").unwrap();
    // println!("0x{:x}", u4);

    // let data : Vec<u8> = (0u8..200u8).collect();
    // print_hex_dump(&data, 0);
    // println!("\n***************************************************************\n");
    // let data2: Vec<u8> = vec![0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    // print_hex_dump(&data2, 0);

    let x: u64 = 0x81000001112AF025;
    let pdb = parse_pdb().unwrap();
    let addr = Address::from_base(0);
    let (offset, handler, required_len) = pdb.decompose(&addr,"_MMPTE_HARDWARE.Valid").unwrap();
    println!("Is valid bit: {}", handler(x));

    let (offset, handler, required_len) = pdb.decompose(&addr,"_MMPTE_HARDWARE.NoExecute").unwrap();
    println!("NX bit: {}", handler(x));

    let (offset, handler, required_len) = pdb.decompose(&addr,"_MMPTE_HARDWARE.Write").unwrap();
    println!("Write bit: {}", handler(x));

    let (offset, handler, required_len) = pdb.decompose(&addr,"_MMPTE_HARDWARE.CopyOnWrite").unwrap();
    println!("CopyOnWrite bit: {}", handler(x));


    Ok(())
    
}
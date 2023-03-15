use clap::{App, Arg};
use lpus::utils::mask_cast::MaskCast;
use lpus::{driver_state::DriverState, scan_eprocess};
use lpus::address::*;
use lpus::pdb_store::*;
use winapi::um::winbase::AddAtomW;
use lpus::utils::*;
use std::error::Error;
use std::mem::{size_of};

fn main() {
    let pdb = parse_pdb().unwrap();
    let pfn_db = pdb.get_offset_r("MmPfnDatabase").unwrap();
    let mmpfn = pdb.structs.get("_HARDWARE_PTE").unwrap();
    println!("PFN db: 0x{:x}", pfn_db);
    println!("{:?}", mmpfn);
    
}
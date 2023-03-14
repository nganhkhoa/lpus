pub mod paging_structs;
pub mod paging_traverse;

use std::error::Error;

use paging_structs::PTE;
use paging_traverse::*;
use crate::driver_state::DriverState;

type BoxResult<T> = Result<T, Box<dyn Error>>;

pub fn scan_rwx_pages(driver: &DriverState, cr3: u64) -> BoxResult<Vec<PTE>>{
    let mut result: Vec<PTE> = Vec::new(); 
    let pte_table = list_all_pte(&driver, cr3);

    for pte in pte_table {
        if pte.is_present() {
            if pte.is_executable(&driver).unwrap() && pte.is_writable(&driver).unwrap() {
                result.push(pte);
            }                
        } 
    }
    Ok(result)
}

pub fn scan_injected_pages(driver: &DriverState, cr3: u64) {
    
}
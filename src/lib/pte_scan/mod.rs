pub mod paging_structs;
pub mod paging_traverse;

use std::error::Error;

use paging_structs::*;
use paging_traverse::*;
use crate::driver_state::DriverState;

type BoxResult<T> = Result<T, Box<dyn Error>>;


pub fn is_rwx_page(driver: &DriverState, pte: &PTE) -> bool {
    return pte.is_executable(&driver).unwrap() && pte.is_writable(&driver).unwrap()
}

pub fn is_shared_exec_page(driver: &DriverState, pte: &PTE, pfn_entry: &MMPFN) -> bool {
    return pte.is_executable(driver).unwrap() && !pfn_entry.is_shared_mem(driver).unwrap();
}

pub fn scan_rwx_pages(driver: &DriverState, cr3: u64) -> BoxResult<Vec<PTE>>{
    let mut result: Vec<PTE> = Vec::new(); 
    let pte_table = list_all_pte(driver, cr3);

    for pte in pte_table {
        if pte.is_present() {
            if is_rwx_page(driver, &pte) {
                result.push(pte);
            } 
        }
    }
    Ok(result)
}

pub fn scan_private_exec_pages(driver: &DriverState, cr3: u64) -> BoxResult<Vec<PTE>>{
    let mut result: Vec<PTE> = Vec::new();
    let pte_table = list_all_pte(driver, cr3);
    for pte in pte_table {
        if pte.is_present(){
            let pfn = pte.get_pfn(driver).unwrap_or(0);
            if pfn == 0 {
                continue;
            }
            let pfn_entry = MMPFN::new(driver, pfn);
            if is_shared_exec_page(driver, &pte, &pfn_entry) {
                result.push(pte);
            }
        }
    }
    Ok(result)
}

pub fn scan_injected_pages(driver: &DriverState, cr3: u64) -> BoxResult<Vec<PTE>> {
    // Scanning using both criteria
    let mut result: Vec<PTE> = Vec::new();
    let pte_table = list_all_pte(driver, cr3);
    for pte in pte_table {
        if pte.is_present() {
            if is_rwx_page(driver, &pte) {
                result.push(pte);
                continue;
            } 

            let pfn = pte.get_pfn(driver).unwrap_or(0);
            if pfn == 0 {
                continue;
            }
            
            let pfn_entry = MMPFN::new(driver, pfn);
            if is_shared_exec_page(driver, &pte, &pfn_entry) {
                result.push(pte);
            }
        }
    }

    Ok(result)
}
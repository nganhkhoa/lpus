use crate::driver_state::DriverState;
use super::paging_structs::*;
use std::error::Error;


type BoxResult<T> = Result<T, Box<dyn Error>>;

// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/inc/amd64.h#L2594 (This is wrong!)
// https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
const HIGHEST_USER_ADDRESS : u64 = 0x7FFFFFFFFFFF;
static mut PTE_BASE : u64 = 0;

pub fn startup(driver_state: &DriverState) {

}

pub fn list_all_pml4e(driver_state: &DriverState, cr3: u64) -> Vec<PTE> {   
    /* Return a list of all presenting PML4 entries*/
    let mut pml4e_list : Vec<PTE> = Vec::new();
    for index in 0..512 {
        let vaddr = index << 39;
        
        // Only loop through usermode pages
        if vaddr > HIGHEST_USER_ADDRESS {
            break;
        }

        let entry_addr = (cr3 & 0xffffffffff000) | (index  << 3);
        let new_entry = PTE::from_addr(driver_state, entry_addr);
        if new_entry.is_present() {
            // println!("[*] PML4 entry number {:?}: {:?}", index, new_entry);
            pml4e_list.push(new_entry);
        }        
    }
    return pml4e_list;
}

pub fn list_all_pdpte(driver_state: &DriverState, cr3: u64) -> Vec<PTE> {
    /* Return a list of all presenting PDPTE */

    let pml4e_list = list_all_pml4e(driver_state, cr3);
    let mut pdpte_list : Vec<PTE> = Vec::new();
    for pml4e in pml4e_list {
        for index in 0..512 {
            // We don't need to check against HIGHEST_USER_ADDRESS here
            // Since HIGHEST_USER_ADDRESS is paged align, if the top of the page is in userland then the whole page will be too
            // The check for if the top of the page is in userland is already in list_pml4e
            // ptenum still perform the check for some reason

            // TODO: Read the whole PDPT instead of each entry one by one (IO is slow!)

            // println!("Deref address {:x}", (pml4e.pfn.value() << 12) | (index << 3));
            let entry_addr = (pml4e.get_pfn(driver_state).unwrap() << 12) | (index << 3);
            let new_entry = PTE::from_addr(driver_state, entry_addr);
            if new_entry.is_present() {
                // println!("[*] PDPT entry number {:?}: {:?}", index, new_entry);
                pdpte_list.push(new_entry);
            }
        }
    }
    return pdpte_list;
}

pub fn list_all_pde(driver_state: &DriverState, cr3: u64) -> Vec<PTE> {
    /* Return a list of all presenting PDE*/
    // Handle both PDE and PDPTE for large pages (1gb pages)

    let pdpte_list = list_all_pdpte(driver_state, cr3);
    let mut pde_list : Vec<PTE> = Vec::new();
    for pdpte in pdpte_list {
        if pdpte.is_large_page(driver_state).unwrap_or(false) {
            // Return this value so it can be handled along with all other normal pages
            pde_list.push(pdpte);
            continue;
        }

        for index in 0..512 {
            let entry_addr = (pdpte.get_pfn(driver_state).unwrap() << 12) | (index << 3);
            let new_entry = PTE::from_addr(driver_state, entry_addr);
            if new_entry.is_present() {
                // println!("[*] PDE entry number {:?}: {:?}", index, new_entry);
                pde_list.push(new_entry);
            }
        }
    } 
    return pde_list;
}

pub fn list_all_pte(driver_state: &DriverState, cr3: u64) -> Vec<PTE>{
    let pde_list = list_all_pde(driver_state, cr3);
    let mut pte_list: Vec<PTE> = Vec::new();
    for pde in pde_list {
        if pde.is_large_page(driver_state).unwrap_or(false) {
            // Return this value so it can be handled along with all other normal pages
            // The list now includes PDPTE and PDE for large pages and PTE for normal pages 
            pte_list.push(pde);
            continue;
        }

        for index in 0..512 {
            let entry_addr = (pde.get_pfn(driver_state).unwrap() << 12) | (index << 3);
            let new_entry = PTE::from_addr(driver_state, entry_addr);
            // println!("[*] PTE entry number {:?}: {:?}", index, data);
            // pte_list.push((data, pte_addr));
            pte_list.push(new_entry);
        }
    }
    return pte_list;
}

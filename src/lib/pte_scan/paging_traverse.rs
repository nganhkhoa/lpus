use crate::driver_state::DriverState;
use super::paging_structs::*;

// Try using the new decompose method
// TODO: In this new way, we have to read 64-bit everytime we want to query just 1 bit --> must improve somehow

// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/inc/amd64.h#L2594 (This is wrong!)
// https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
const HIGHEST_USER_ADDRESS : u64 = 0x7FFFFFFFFFFF;

pub fn list_all_pml4e(driver_state: &DriverState, cr3: u64) -> Vec<PTE> {   
    /* Return a list of all presenting PML4 entries*/
    let mut pml4e_list : Vec<PTE> = Vec::new();
    for index in 0..512 {
        let vaddr = index << 39;
        
        // Only loop through usermode pages
        if vaddr > HIGHEST_USER_ADDRESS {
            break;
        }

        // let data : u64 = driver_state.deref_physical_addr((cr3 & 0xffffffffff000) | (index  << 3));
        let entry_addr = (cr3 & 0xffffffffff000) | (index  << 3);
        let new_entry = PTE::new(driver_state, entry_addr);
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
            // TODO: Handle large pages.

            // println!("Deref address {:x}", (pml4e.pfn.value() << 12) | (index << 3));
            let entry_addr = (pml4e.get_pfn(driver_state).unwrap() << 12) | (index << 3);
            let new_entry = PTE::new(driver_state, entry_addr);
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

    let pdpte_list = list_all_pdpte(driver_state, cr3);
    let mut pde_list : Vec<PTE> = Vec::new();
    for pdpte in pdpte_list {
        for index in 0..512 {
            let entry_addr = (pdpte.get_pfn(driver_state).unwrap() << 12) | (index << 3);
            let new_entry = PTE::new(driver_state, entry_addr);
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
        for index in 0..512 {
            let entry_addr = (pde.get_pfn(driver_state).unwrap() << 12) | (index << 3);
            let new_entry = PTE::new(driver_state, entry_addr);
            // println!("[*] PTE entry number {:?}: {:?}", index, data);
            // pte_list.push((data, pte_addr));
            pte_list.push(new_entry);
        }
    }
    return pte_list;
}

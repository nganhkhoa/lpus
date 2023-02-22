use clap::{App, Arg};
use crate::{driver_state::DriverState, scan_eprocess};
use crate::paging_structs::*;

// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/inc/amd64.h#L2594 (This is wrong!)
// https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
const HIGHEST_USER_ADDRESS : u64 = 0x7FFFFFFFFFFF;

pub fn list_all_pml4e(driver_state: &DriverState, cr3: u64) -> Vec<PML4E> {   
    /* Return a list of all presenting PML4 entries*/
    let mut pml4e_list : Vec<PML4E> = Vec::new();
    for index in 0..512 {
        let vaddr = index << 39;
        
        // Only loop through usermode pages
        if vaddr > HIGHEST_USER_ADDRESS {
            break;
        }
        let data : u64 = driver_state.deref_physical_addr((cr3 & 0xffffffffff000) | (index  << 3));
        let new_entry = PML4E::new(data);
        if (new_entry.present.value() != 0) {
            // println!("[*] PML4 entry number {:?}: {:?}", index, new_entry);
            pml4e_list.push(new_entry);
        }        
    }
    return pml4e_list;
}

pub fn list_all_pdpte(driver_state: &DriverState, cr3: u64) -> Vec<PDPTE> {
    /* Return a list of all presenting PDPTE */

    let pml4e_list = list_all_pml4e(driver_state, cr3);
    let mut pdpte_list : Vec<PDPTE> = Vec::new();
    for pml4e in pml4e_list {
        for index in 0..512 {
            // We don't need to check against HIGHEST_USER_ADDRESS here
            // Since HIGHEST_USER_ADDRESS is paged align, if the top of the page is in userland then the whole page will be too
            // The check for if the top of the page is in userland is already in list_pml4e
            // ptenum still perform the check for some reason

            // TODO: Read the whole PDPT instead of each entry one by one (IO is slow!)
            // println!("Deref address {:x}", (pml4e.pfn.value() << 12) | (index << 3));
            let data: u64 = driver_state.deref_physical_addr((pml4e.pfn.value() << 12) | (index << 3));
            let new_entry = PDPTE::new(data);
            if (new_entry.present.value() != 0) {
                // println!("[*] PDPT entry number {:?}: {:?}", index, new_entry);
                pdpte_list.push(new_entry);
            }
        }
    }
    return pdpte_list;
}

pub fn list_all_pde(driver_state: &DriverState, cr3: u64) -> Vec<PDE> {
    /* Return a list of all presenting PDE*/

    let pdpte_list = list_all_pdpte(driver_state, cr3);
    let mut pde_list : Vec<PDE> = Vec::new();
    for pdpte in pdpte_list {
        for index in 0..512 {
            let data: u64 = driver_state.deref_physical_addr((pdpte.pfn.value() << 12) | (index << 3));
            let new_entry = PDE::new(data);
            if (new_entry.present.value() != 0) {
                // println!("[*] PDE entry number {:?}: {:?}", index, new_entry);
                pde_list.push(new_entry);
            }
        }
    } 
    return pde_list;
}

pub fn list_all_pte(driver_state: &DriverState, cr3: u64) {
    let pde_list = list_all_pde(driver_state, cr3);
    for pde in pde_list {
        for index in 0..512 {
            let data: u64 = driver_state.deref_physical_addr((pde.pfn.value() << 12) | (index << 3));
            // println!("[*] PDE entry number {:?}: {:?}", index, data);
            
            // TODO: Parse PTE
            // TODO: Still crash at some high-address PTE
        }
    }
}

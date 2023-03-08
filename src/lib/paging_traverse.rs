use crate::driver_state::DriverState;
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
        if new_entry.is_present() {
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
            let data: u64 = driver_state.deref_physical_addr((pml4e.get_pfn() << 12) | (index << 3));
            let new_entry = PDPTE::new(data);
            if new_entry.is_present() {
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
            if new_entry.is_present() {
                // println!("[*] PDE entry number {:?}: {:?}", index, new_entry);
                pde_list.push(new_entry);
            }
        }
    } 
    return pde_list;
}

pub fn list_all_pte(driver_state: &DriverState, cr3: u64) -> Vec<Box<dyn PagingStruct>>{
    let pde_list = list_all_pde(driver_state, cr3);
    let mut pte_list: Vec<Box<dyn PagingStruct>> = Vec::new();
    for pde in pde_list {
        for index in 0..512 {
            let pte_addr = (pde.pfn.value() << 12) | (index << 3);
            let data: u64 = driver_state.deref_physical_addr(pte_addr);
            // println!("[*] PTE entry number {:?}: {:?}", index, data);
            // pte_list.push((data, pte_addr));

            // TODO: Parse PTE
            // TODO: Fix crashes at some high-address PTE
            let new_entry = parse_pte(data);
            match new_entry {
                Ok(entry) => {
                    pte_list.push(entry);
                }
                Err(msg) => {
                    // println!("Error at PTE entry {:?}: {:?}", index, msg);
                }
            }

        }
    }
    return pte_list;
}

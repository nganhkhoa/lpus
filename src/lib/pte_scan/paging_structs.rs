use std::error::Error;
use crate::address::{Address, self};
use crate::driver_state::{*, self};
use crate::utils::get_bit_mask_handler;

// Ref: https://back.engineering/23/08/2020/
// Ref: https://blog.efiens.com/post/luibo/address-translation-revisited/

type BoxResult<T> = Result<T, Box<dyn Error>>;

#[derive(PartialEq)]
pub enum PageState {
    HARDWARE,
    TRANSITION,
    PROTOTYPE,
    INVALID
}

// Metadata object for PTE
// Since PML4E, PDPTE and PDE have the same structure, this struct can be used for all paging struct
pub struct PTE {
    pub state: PageState,
    pub address: Address
}

impl PTE {
    pub fn new(driver: &DriverState, addr: u64) -> Self {
        let addr_obj = Address::from_base(addr);
        let is_hardware: u64 = driver.decompose_physical(&addr_obj, "_MMPTE_HARDWARE.Valid").unwrap();
        if is_hardware != 0 {
            return Self{state: PageState::HARDWARE, address: addr_obj};
        }

        let is_prototype: u64 = driver.decompose_physical(&addr_obj, "_MMPTE_PROTOTYPE.Prototype").unwrap();
        if is_prototype != 0 {
            return Self{state: PageState::PROTOTYPE, address: addr_obj};
        }

        let is_transition: u64 = driver.decompose_physical(&addr_obj, "_MMPTE_TRANSITION.Transition").unwrap();
        if is_transition != 0 {
            return Self{state: PageState::TRANSITION, address: addr_obj};
        }
        return Self{state: PageState::INVALID, address: addr_obj};
    }

    pub fn is_present(&self) -> bool{
        return self.state == PageState::HARDWARE;
    }

    pub fn get_pfn(&self, driver: &DriverState) -> BoxResult<u64> {
        if self.state == PageState::HARDWARE {
            let pfn: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.PageFrameNumber").unwrap();
            return Ok(pfn);
        } else if self.state == PageState::TRANSITION {
            let pfn: u64 = driver.decompose_physical(&self.address, "_MMPTE_TRANSITION.PageFrameNumber").unwrap();
            return Ok(pfn);
        } else {
            return Err("No PFN in this state of PTE".into());
        }
    }

    pub fn is_executable(&self, driver: &DriverState) -> BoxResult<bool> {
        if self.state == PageState::HARDWARE {
            let nx_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.NoExecute").unwrap();
            return Ok(nx_bit == 0);
        }

        return Err("Executable page test is not implemented for this state".into())
    }

    pub fn is_writable(&self, driver: &DriverState) -> BoxResult<bool> {
        if self.state == PageState::HARDWARE {
            let write_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.Write").unwrap();
            return Ok(write_bit != 0);
        }

        return Err("Writable page test is not implemented for this state".into())
    }

    pub fn is_large_page(&self, driver: &DriverState) -> BoxResult<bool> {
        if self.state == PageState::HARDWARE {
            let large_page_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.LargePage").unwrap();
            Ok(large_page_bit != 0)
        } else {
            // Large page is always non-paged
            Ok(false)
        }
    }
}

pub struct MMPFN {
    index: u64,
    address: Address,
}

impl MMPFN {
    pub fn new(driver: &DriverState, index: u64) -> Self {
        let kernel_base = driver.get_kernel_base();
        let pfn_db_base = kernel_base + driver.pdb_store.get_offset_r("MmPfnDatabase").unwrap();
        let pfn_entry_size = driver.pdb_store.get_offset_r("struct_size").unwrap();
        let entry_address = pfn_db_base + index * pfn_entry_size; 
        Self { index: index, address: entry_address }
    }

    pub fn is_shared_mem(&self, driver: &DriverState) -> BoxResult<bool> {
        let u4_union: u64 = driver.decompose(&self.address, "_MMPFN.u4")?;
        let handler = get_bit_mask_handler(63, 1);
        let prototype_pte_bit = handler(u4_union);
        Ok(prototype_pte_bit == 0)
    }
}
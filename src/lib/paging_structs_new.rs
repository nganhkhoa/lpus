use std::convert::TryInto;
use std::error::Error;
use bit_struct::*; 
use std::any::Any;
use crate::address::Address;
use crate::driver_state::*;

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
    state: PageState,
    address: Address
}

impl PTE {
    pub fn new(driver: &DriverState, addr: u64) -> Self {
        let addr_obj = Address::from_base(addr);
        let is_hardware: u8 = driver.decompose_physical(&addr_obj, "_MMPTE_HARDWARE.Valid").unwrap();
        if is_hardware != 0 {
            return Self{state: PageState::HARDWARE, address: addr_obj};
        }

        let is_prototype: u8 = driver.decompose_physical(&addr_obj, "_MMPTE_PROTOTYPE.Prototype").unwrap();
        if is_prototype != 0 {
            return Self{state: PageState::PROTOTYPE, address: addr_obj};
        }

        let is_transition: u8 = driver.decompose_physical(&addr_obj, "_MMPTE_TRANSITION.Transition").unwrap();
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
        } else if (self.state == PageState::TRANSITION) {
            let pfn: u64 = driver.decompose_physical(&self.address, "_MMPTE_TRANSITION.PageFrameNumber").unwrap();
            return Ok(pfn);
        } else {
            return Err("No PFN in this state of PTE".into());
        }
    }
}
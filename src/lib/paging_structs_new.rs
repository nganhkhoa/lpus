use std::error::Error;
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
}
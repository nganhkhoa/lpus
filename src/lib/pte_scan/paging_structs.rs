use std::error::Error;
use  std::convert::From;
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
    PAGEFILE
}

const MM_PROTECT_ACCESS: u64 = 7;


// No official document, following: https://github.com/f-block/volatility-plugins/blob/main/ptenum.py#L110
// and: https://reactos.org/wiki/Techwiki:Memory_management_in_the_Windows_XP_kernel (kinda old but still seems valid)
pub enum PteProtection {
    MM_ZERO_ACCESS,
    MM_READONLY,
    MM_EXECUTE,
    MM_EXECUTE_READ,
    MM_READWRITE, 
    MM_WRITECOPY,
    MM_EXECUTE_READWRITE,
    MM_EXECUTE_WRITECOPY,   
}

impl From<u64> for PteProtection {
    fn from(value: u64) -> Self {
        match value {
            // 0 => PteProtection::MM_ZERO_ACCESS,
            1 => PteProtection::MM_READONLY,
            2 => PteProtection::MM_EXECUTE,
            3 => PteProtection::MM_EXECUTE_READ,
            4 => PteProtection::MM_READWRITE,
            5 => PteProtection::MM_WRITECOPY,
            6 => PteProtection::MM_EXECUTE_READWRITE,
            7 => PteProtection::MM_EXECUTE_WRITECOPY,
            _ => panic!("Invalid protection value {} for PTE", value)
        }
    }
}

impl PteProtection {
    pub fn is_executable(&self) -> bool {
        match self {
            PteProtection::MM_EXECUTE | PteProtection::MM_EXECUTE_READ | PteProtection::MM_EXECUTE_READWRITE | PteProtection::MM_EXECUTE_WRITECOPY => true,
            _ => false
        }
    }

    pub fn is_writable(&self) -> bool {
        match self {
            PteProtection::MM_READWRITE | PteProtection::MM_WRITECOPY | PteProtection::MM_EXECUTE_READWRITE | PteProtection::MM_EXECUTE_WRITECOPY => true,
            _ => false
        }
    }
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
        return Self{state: PageState::PAGEFILE, address: addr_obj};
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
        // Following: https://github.com/f-block/volatility-plugins/blob/main/ptenum.py
        if self.state == PageState::HARDWARE {
            let nx_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.NoExecute")?;
            return Ok(nx_bit == 0);
        } else if self.state == PageState::TRANSITION {
            let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_TRANSITION.Protection")?;
            return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_executable());
        } else if self.state == PageState::PROTOTYPE {
            let proto_address: u64 = driver.decompose_physical(&self.address, "_MMPTE_PROTOTYPE.ProtoAddress")?;
            
            if proto_address == 0xffffffff0000 {
                let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.Protection")?;
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_executable());
            }

            let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_PROTOTYPE.Protection")?;
            if protection == 0 {
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_executable());
            } else {
                let proto_pte = PTE::new(driver, proto_address);
                // If the prototype pte has prototype bit set, apply the _MMPTE_SUBSECTION struct
                // Otherwise handle it like a normal MMU PTE
                if proto_pte.state == PageState::PROTOTYPE {
                    let proto_protection: u64 = driver.decompose_physical(&proto_pte.address, "_MMPTE_SUBSECTION.Protection")?;
                    return Ok(PteProtection::from(proto_protection & MM_PROTECT_ACCESS).is_executable());
                } else {
                    return proto_pte.is_executable(driver);
                }
            }
        } else if self.state == PageState::PAGEFILE {
            let page_file_high: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.PageFileHigh")?;
            if page_file_high != 0 {
                let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.Protection")?;
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_executable());
            } else {
                println!("Page is in an unknown state");
                return Ok(false);
            }
        }
        return Err("Executable page test is not implemented for this state".into())
    }

    pub fn is_writable(&self, driver: &DriverState) -> BoxResult<bool> {
        // Get the write access right similar to the way we get the exec right
        if self.state == PageState::HARDWARE {
            let write_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.Write").unwrap();
            return Ok(write_bit != 0);
        } else if self.state == PageState::TRANSITION {
            let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_TRANSITION.Protection")?;
            return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_writable());
        } else if self.state == PageState::PROTOTYPE {
            let proto_address: u64 = driver.decompose_physical(&self.address, "_MMPTE_PROTOTYPE.ProtoAddress")?;
            
            if proto_address == 0xffffffff0000 {
                let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.Protection")?;
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_writable());
            }

            let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_PROTOTYPE.Protection")?;
            if protection == 0 {
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_writable());
            } else {
                let proto_pte = PTE::new(driver, proto_address);
                // If the prototype pte has prototype bit set, apply the _MMPTE_SUBSECTION struct
                // Otherwise handle it like a normal MMU PTE
                if proto_pte.state == PageState::PROTOTYPE {
                    let proto_protection: u64 = driver.decompose_physical(&proto_pte.address, "_MMPTE_SUBSECTION.Protection")?;
                    return Ok(PteProtection::from(proto_protection & MM_PROTECT_ACCESS).is_writable());
                } else {
                    return proto_pte.is_writable(driver);
                }
            }
        } else if self.state == PageState::PAGEFILE {
            let page_file_high: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.PageFileHigh")?;
            if page_file_high != 0 {
                let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.Protection")?;
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_writable());
            } else {
                println!("Page is in an unknown state");
                return Ok(false);
            }
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
        // Getting _MMPFN.u4.PrototypePte
        let prototype_pte_bit = handler(u4_union);
        Ok(prototype_pte_bit == 0)
    }
}
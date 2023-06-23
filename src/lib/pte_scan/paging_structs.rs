use std::error::Error;
use  std::convert::From;
use crate::address::Address;
use crate::driver_state::*;
use crate::utils::mask_cast::get_bit_mask_handler;

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
            0 => PteProtection::MM_ZERO_ACCESS,
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
    pub address: Address,
    pub value: u64
}

impl PTE {

    pub fn from_addr(driver: &DriverState, addr: u64) -> Self {
        let addr_obj = Address::from_base(addr);
        // let is_hardware: u64 = driver.decompose_physical(&addr_obj, "_MMPTE_HARDWARE.Valid").unwrap();
        // if is_hardware != 0 {
        //     return Self{state: PageState::HARDWARE, address: addr_obj};
        // }

        // let is_prototype: u64 = driver.decompose_physical(&addr_obj, "_MMPTE_PROTOTYPE.Prototype").unwrap();
        // if is_prototype != 0 {
        //     return Self{state: PageState::PROTOTYPE, address: addr_obj};
        // }

        // let is_transition: u64 = driver.decompose_physical(&addr_obj, "_MMPTE_TRANSITION.Transition").unwrap();
        // if is_transition != 0 {
        //     return Self{state: PageState::TRANSITION, address: addr_obj};
        // }
        // return Self{state: PageState::PAGEFILE, address: addr_obj};
        let pte_value = driver.deref_physical_addr(addr);
        let (offset, hardware_handler, _) = driver.pdb_store.decompose(&addr_obj, "_MMPTE_HARDWARE.Valid").unwrap();
        assert!(offset.address() == addr_obj.address(), "Fault in decomposing PTE");
        
        let is_hardware = hardware_handler(pte_value);
        if is_hardware != 0 {
            return Self{state: PageState::HARDWARE, address: addr_obj, value: pte_value};
        }
        let (_, prototype_handler, _) = driver.pdb_store.decompose(&addr_obj, "_MMPTE_PROTOTYPE.Prototype").unwrap();
        let is_prototype = prototype_handler(pte_value);
        if is_prototype != 0 {
            return Self{state: PageState::PROTOTYPE, address: addr_obj, value: pte_value};
        }

        let (_, trans_handler, _) = driver.pdb_store.decompose(&addr_obj, "_MMPTE_TRANSITION.Transition").unwrap();
        let is_transition = trans_handler(pte_value);
        if is_transition != 0 {
            return Self{state: PageState::TRANSITION, address: addr_obj, value: pte_value};
        }
        return Self{state: PageState::PAGEFILE, address: addr_obj, value: pte_value};

    }

    pub fn from_value(driver: &DriverState, pte_value: u64) -> Self {
        let addr_obj = Address::from_base(0);
        let (offset, hardware_handler, _) = driver.pdb_store.decompose(&addr_obj, "_MMPTE_HARDWARE.Valid").unwrap();
        
        let is_hardware = hardware_handler(pte_value);
        if is_hardware != 0 {
            return Self{state: PageState::HARDWARE, address: addr_obj, value: pte_value};
        }
        let (_, prototype_handler, _) = driver.pdb_store.decompose(&addr_obj, "_MMPTE_PROTOTYPE.Prototype").unwrap();
        let is_prototype = prototype_handler(pte_value);
        if is_prototype != 0 {
            return Self{state: PageState::PROTOTYPE, address: addr_obj, value: pte_value};
        }

        let (_, trans_handler, _) = driver.pdb_store.decompose(&addr_obj, "_MMPTE_TRANSITION.Transition").unwrap();
        let is_transition = trans_handler(pte_value);
        if is_transition != 0 {
            return Self{state: PageState::TRANSITION, address: addr_obj, value: pte_value};
        }
        return Self{state: PageState::PAGEFILE, address: addr_obj, value: pte_value};
    }

    pub fn get_pte_field(&self, driver: &DriverState, name: &str) -> u64 {
        let (addr, handler, len) = driver.pdb_store.decompose(&self.address, name).unwrap();
        handler(self.value)
    }

    pub fn is_present(&self) -> bool{
        return self.state == PageState::HARDWARE;
    }

    // pub fn test_present_exact(&self, driver: &DriverState) -> bool {
    //     let is_hardware: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.Valid").unwrap();
    //     return is_hardware != 0;
    // }

    pub fn get_pfn(&self, driver: &DriverState) -> BoxResult<u64> {
        if self.state == PageState::HARDWARE {
            // let pfn: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.PageFrameNumber").unwrap();
            let pfn = self.get_pte_field(driver, "_MMPTE_HARDWARE.PageFrameNumber");
            return Ok(pfn);
        } else if self.state == PageState::TRANSITION {
            // let pfn: u64 = driver.decompose_physical(&self.address, "_MMPTE_TRANSITION.PageFrameNumber").unwrap();
            let pfn = self.get_pte_field(driver, "_MMPTE_TRANSITION.PageFrameNumber");
            return Ok(pfn);
        } else {
            return Err("No PFN in this state of PTE".into());
        }
    }

    pub fn is_executable(&self, driver: &DriverState) -> BoxResult<bool> {
        // Following: https://github.com/f-block/volatility-plugins/blob/main/ptenum.py
        if self.state == PageState::HARDWARE {
            // let nx_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.NoExecute")?;
            let nx_bit = self.get_pte_field(driver, "_MMPTE_HARDWARE.NoExecute");
            return Ok(nx_bit == 0);
        } else if self.state == PageState::TRANSITION {
            // let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_TRANSITION.Protection")?;
            let protection = self.get_pte_field(driver, "_MMPTE_TRANSITION.Protection");
            return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_executable());
        } else if self.state == PageState::PROTOTYPE {
            // let proto_address: u64 = driver.decompose_physical(&self.address, "_MMPTE_PROTOTYPE.ProtoAddress")?;
            let proto_address = self.get_pte_field(driver, "_MMPTE_PROTOTYPE.ProtoAddress");
            if proto_address == 0xffffffff0000 {
                // let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.Protection")?;
                let protection = self.get_pte_field(driver, "_MMPTE_SOFTWARE.Protection");
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_executable());
            }

            // let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_PROTOTYPE.Protection")?;
            let protection = self.get_pte_field(driver, "_MMPTE_PROTOTYPE.Protection");
            if protection != 0 {
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_executable());
            } else {
                let proto_pte = PTE::from_addr(driver, proto_address);
                // If the prototype pte has prototype bit set, apply the _MMPTE_SUBSECTION struct
                // Otherwise handle it like a normal MMU PTE
                if proto_pte.state == PageState::PROTOTYPE {
                    // let proto_protection: u64 = driver.decompose_physical(&proto_pte.address, "_MMPTE_SUBSECTION.Protection")?;
                    let proto_protection = proto_pte.get_pte_field(driver, "_MMPTE_SUBSECTION.Protection");
                    return Ok(PteProtection::from(proto_protection & MM_PROTECT_ACCESS).is_executable());
                } else {
                    return proto_pte.is_executable(driver);
                }
            }
        } else if self.state == PageState::PAGEFILE {
            // let page_file_high: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.PageFileHigh")?;
            let page_file_high = self.get_pte_field(driver, "_MMPTE_SOFTWARE.PageFileHigh");
            if page_file_high != 0 {
                // let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.Protection")?;
                let protection = self.get_pte_field(driver, "_MMPTE_SOFTWARE.Protection");
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_executable());
            } else {
                // println!("Page is in an unknown state");
                return Ok(false);
            }
        }
        return Err("Executable page test is not implemented for this state".into())
    }

    pub fn is_writable(&self, driver: &DriverState) -> BoxResult<bool> {
        // Get the write access right similar to the way we get the exec right
        if self.state == PageState::HARDWARE {
            // let write_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.Write").unwrap();
            let write_bit = self.get_pte_field(driver, "_MMPTE_HARDWARE.Write");
            if write_bit != 0 {
                return Ok(true);
            }
            // Detection for writable shared pages
            // Writable shared pages may have write bit unset, but the copy-on-write bit is still set to 1
            // Mainly to handle DirtyVanity
            // let copy_on_write_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.CopyOnWrite").unwrap();
            let copy_on_write_bit = self.get_pte_field(driver, "_MMPTE_HARDWARE.CopyOnWrite");
            return Ok(copy_on_write_bit != 0);

        } else if self.state == PageState::TRANSITION {
            // let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_TRANSITION.Protection")?;
            let protection = self.get_pte_field(driver, "_MMPTE_TRANSITION.Protection");
            return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_writable());
        } else if self.state == PageState::PROTOTYPE {
            // let proto_address: u64 = driver.decompose_physical(&self.address, "_MMPTE_PROTOTYPE.ProtoAddress")?;
            let proto_address = self.get_pte_field(driver, "_MMPTE_PROTOTYPE.ProtoAddress");
            if proto_address == 0xffffffff0000 {
                // let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.Protection")?;
                let protection = self.get_pte_field(driver, "_MMPTE_SOFTWARE.Protection");
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_writable());
            }

            // let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_PROTOTYPE.Protection")?;
            let protection = self.get_pte_field(driver, "_MMPTE_PROTOTYPE.Protection");
            if protection != 0 {
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_writable());
            } else {
                let proto_pte = PTE::from_addr(driver, proto_address);
                // If the prototype pte has prototype bit set, apply the _MMPTE_SUBSECTION struct
                // Otherwise handle it like a normal MMU PTE
                if proto_pte.state == PageState::PROTOTYPE {
                    // let proto_protection: u64 = driver.decompose_physical(&proto_pte.address, "_MMPTE_SUBSECTION.Protection")?;
                    let proto_protection = proto_pte.get_pte_field(driver, "_MMPTE_SUBSECTION.Protection");
                    return Ok(PteProtection::from(proto_protection & MM_PROTECT_ACCESS).is_writable());
                } else {
                    return proto_pte.is_writable(driver);
                }
            }
        } else if self.state == PageState::PAGEFILE {
            // let page_file_high: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.PageFileHigh")?;
            let page_file_high = self.get_pte_field(driver, "_MMPTE_SOFTWARE.PageFileHigh");
            if page_file_high != 0 {
                // let protection: u64 = driver.decompose_physical(&self.address, "_MMPTE_SOFTWARE.Protection")?;
                let protection = self.get_pte_field(driver, "_MMPTE_SOFTWARE.Protection");
                return Ok(PteProtection::from(protection & MM_PROTECT_ACCESS).is_writable());
            } else {
                // println!("Page is in an unknown state");
                return Ok(false);
            }
        }
        return Err("Writable page test is not implemented for this state".into())
    }

    pub fn is_large_page(&self, driver: &DriverState) -> BoxResult<bool> {
        if self.state == PageState::HARDWARE {
            // let large_page_bit: u64 = driver.decompose_physical(&self.address, "_MMPTE_HARDWARE.LargePage").unwrap();
            let large_page_bit = self.get_pte_field(driver, "_MMPTE_HARDWARE.LargePage");
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
        let pfn_symbol = kernel_base + driver.pdb_store.get_offset_r("MmPfnDatabase").unwrap();
        let pfn_db_base: u64 = driver.deref_addr_new(pfn_symbol.address());
        let pfn_entry_size = driver.pdb_store.get_offset_r("_MMPFN.struct_size").unwrap();
        let entry_address = pfn_db_base + index * pfn_entry_size; 
        Self { index: index, address: Address::from_base(entry_address) }
    }

    pub fn is_shared_mem(&self, driver: &DriverState) -> BoxResult<bool> {
        // Getting _MMPFN.u4.PrototypePte
        // TODO: add union support for decompose 
        let u4_union: u64 = driver.decompose(&self.address, "_MMPFN.u4")?;
        // According to windbg
        let handler = get_bit_mask_handler(57, 1);
        let prototype_pte_bit = handler(u4_union);
        Ok(prototype_pte_bit != 0)
    }
}
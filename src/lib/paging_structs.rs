use std::convert::TryInto;
use std::error::Error;
use bit_struct::*; 
use std::any::Any;

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

pub trait PagingStruct: std::fmt::Debug{
    fn as_any(&self) -> &dyn Any;
    fn get_pfn(&self) -> u64;
    fn is_present(&self) -> bool;
    fn is_executable(&self) -> bool;
    fn get_state(&self) -> PageState;   
}

#[derive(Debug)]
pub struct PML4E {
    pub present: u1,    
    pub rw: u1,         
    pub user_supervisor: u1,
    pub page_write_through: u1,
    pub page_cache: u1,
    pub accessed: u1,
    pub Ignored1: u1,
    pub page_size: u1,  // Must be 0 for pml4e
    pub Ignored2: u4,
    pub pfn: u36,       
    pub reserved: u4,   
    pub Ignored3: u11,  
    pub nx: u1          
}

impl PML4E {
    pub fn new(data: u64) -> Self {
        Self { 
            present: (u1::new((data & 1).try_into().unwrap()).unwrap()), 
            rw: (u1::new(((data >> 1) & 1).try_into().unwrap()).unwrap()), 
            user_supervisor: (u1::new(((data >> 2) & 1).try_into().unwrap()).unwrap()), 
            page_write_through: (u1::new(((data >> 3) & 1).try_into().unwrap()).unwrap()), 
            page_cache: (u1::new(((data >> 4) & 1).try_into().unwrap()).unwrap()), 
            accessed: (u1::new(((data >> 5) & 1).try_into().unwrap()).unwrap()), 
            Ignored1: (u1::new(((data >> 6) & 1).try_into().unwrap()).unwrap()), 
            page_size: (u1::new(((data >> 7) & 1).try_into().unwrap()).unwrap()), 
            Ignored2: (u4::new(((data >> 8) & 15).try_into().unwrap()).unwrap()), 
            pfn: (u36::new(((data >> 12) & 68719476735).try_into().unwrap()).unwrap()), 
            reserved: (u4::new(((data >> 48) & 15).try_into().unwrap()).unwrap()), 
            Ignored3: (u11::new(((data >> 52) & 2047).try_into().unwrap()).unwrap()), 
            nx: (u1::new(((data >> 63) & 1).try_into().unwrap()).unwrap()) 
        }
    }

}

impl PagingStruct for PML4E {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_present(&self) -> bool {
        return self.present.value() != 0
    }
    
    fn get_pfn(&self) -> u64{
        return self.pfn.value() 
    } 

    fn is_executable(&self) -> bool {
        return self.nx.value() == 0
    }

    fn get_state(&self) -> PageState {
        return PageState::HARDWARE
    }
}

#[derive(Debug)]
pub struct PDPTE {
    pub present : u1,
    pub rw: u1,
    pub user_supervisor: u1,
    pub page_write: u1,
    pub page_cache: u1,
    pub accessed: u1,
    pub Ignored1: u1,
    pub is_1gb_page: u1,
    pub Ignored2: u4,
    pub pfn: u36,
    pub reserved: u4,
    pub Ignored3: u11,  
    pub nx: u1   
}

impl PDPTE {
    pub fn new(data: u64) -> Self {
        Self { 
            present: (u1::new((data & 1).try_into().unwrap()).unwrap()), 
            rw: (u1::new(((data >> 1) & 1).try_into().unwrap()).unwrap()), 
            user_supervisor: (u1::new(((data >> 2) & 1).try_into().unwrap()).unwrap()), 
            page_write: (u1::new(((data >> 3) & 1).try_into().unwrap()).unwrap()), 
            page_cache: (u1::new(((data >> 4) & 1).try_into().unwrap()).unwrap()), 
            accessed: (u1::new(((data >> 5) & 1).try_into().unwrap()).unwrap()), 
            Ignored1: (u1::new(((data >> 6) & 1).try_into().unwrap()).unwrap()), 
            is_1gb_page: (u1::new(((data >> 7) & 1).try_into().unwrap()).unwrap()), 
            Ignored2: (u4::new(((data >> 8) & 15).try_into().unwrap()).unwrap()), 
            pfn: (u36::new(((data >> 12) & 68719476735).try_into().unwrap()).unwrap()), 
            reserved: (u4::new(((data >> 48) & 15).try_into().unwrap()).unwrap()), 
            Ignored3: (u11::new(((data >> 52) & 2047).try_into().unwrap()).unwrap()), 
            nx: (u1::new(((data >> 63) & 1).try_into().unwrap()).unwrap())
        }
    }
}

impl PagingStruct for PDPTE {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_present(&self) -> bool {
        return self.present.value() != 0
    }
    
    fn get_pfn(&self) -> u64{
        return self.pfn.value() 
    } 

    fn is_executable(&self) -> bool {
        return self.nx.value() == 0
    }

    fn get_state(&self) -> PageState {
        return PageState::HARDWARE
    }
}

#[derive(Debug)]
pub struct PDE {
    pub present : u1,
    pub rw: u1,
    pub user_supervisor: u1,
    pub page_write: u1,
    pub page_cache: u1,
    pub accessed: u1,
    pub Ignored1: u1,
    pub is_2mb_page: u1,
    pub Ignored2: u4,
    pub pfn: u36,
    pub reserved: u4,
    pub Ignored3: u11,  
    pub nx: u1   
}

impl PDE {
    pub fn new (data:u64) -> Self {
        Self { 
            present: (u1::new((data & 1).try_into().unwrap()).unwrap()), 
            rw: (u1::new(((data >> 1) & 1).try_into().unwrap()).unwrap()), 
            user_supervisor: (u1::new(((data >> 2) & 1).try_into().unwrap()).unwrap()), 
            page_write: (u1::new(((data >> 3) & 1).try_into().unwrap()).unwrap()), 
            page_cache: (u1::new(((data >> 4) & 1).try_into().unwrap()).unwrap()), 
            accessed: (u1::new(((data >> 5) & 1).try_into().unwrap()).unwrap()), 
            Ignored1: (u1::new(((data >> 6) & 1).try_into().unwrap()).unwrap()), 
            is_2mb_page: (u1::new(((data >> 7) & 1).try_into().unwrap()).unwrap()), 
            Ignored2: (u4::new(((data >> 8) & 15).try_into().unwrap()).unwrap()), 
            pfn: (u36::new(((data >> 12) & 68719476735).try_into().unwrap()).unwrap()), 
            reserved: (u4::new(((data >> 48) & 15).try_into().unwrap()).unwrap()), 
            Ignored3: (u11::new(((data >> 52) & 2047).try_into().unwrap()).unwrap()), 
            nx: (u1::new(((data >> 63) & 1).try_into().unwrap()).unwrap())
        }
    }
}

impl PagingStruct for PDE {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_present(&self) -> bool {
        return self.present.value() != 0
    }
    
    fn get_pfn(&self) -> u64{
        return self.pfn.value() 
    } 

    fn is_executable(&self) -> bool {
        return self.nx.value() == 0
    }

    fn get_state(&self) -> PageState {
        return PageState::HARDWARE
    }
}

// PTE states: http://blog.rekall-forensic.com/2014/10/windows-virtual-address-translation-and.html
// Structure of each states: https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2104%2021H1%20(May%202021%20Update)/_MMPTE
// And also the paper

#[derive(Debug)]
pub struct MMPTE_HARDWARE {
    pub Valid: u1,
    pub Dirty1: u1,
    pub Owner: u1,
    pub WriteThrough: u1,
    pub CacheDisable: u1,
    pub Accessed: u1,
    pub Dirty: u1,
    pub LargePage: u1,
    pub Global: u1,
    pub CopyOnWrite: u1,
    pub Unused: u1,
    pub Write: u1,
    pub PageFrameNumber: u36,
    pub ReservedForHardware: u4,
    pub ReservedForSoftware: u4,
    pub WsleAge: u4,
    pub WsleProtection: u3,
    pub NoExecute: u1
}

impl MMPTE_HARDWARE {
    pub fn new(data: u64) -> Self {
        Self {
            Valid: (u1::new((data & 1).try_into().unwrap()).unwrap()), 
            Dirty1: (u1::new(((data >> 1) & 1).try_into().unwrap()).unwrap()), 
            Owner: (u1::new(((data >> 2) & 1).try_into().unwrap()).unwrap()), 
            WriteThrough: (u1::new(((data >> 3) & 1).try_into().unwrap()).unwrap()), 
            CacheDisable: (u1::new(((data >> 4) & 1).try_into().unwrap()).unwrap()), 
            Accessed: (u1::new(((data >> 5) & 1).try_into().unwrap()).unwrap()), 
            Dirty: (u1::new(((data >> 6) & 1).try_into().unwrap()).unwrap()), 
            LargePage: (u1::new(((data >> 7) & 1).try_into().unwrap()).unwrap()), 
            Global: (u1::new(((data >> 8) & 1).try_into().unwrap()).unwrap()), 
            CopyOnWrite: (u1::new(((data >> 9) & 1).try_into().unwrap()).unwrap()), 
            Unused: (u1::new(((data >> 10) & 1).try_into().unwrap()).unwrap()), 
            Write: (u1::new(((data >> 11) & 1).try_into().unwrap()).unwrap()), 
            PageFrameNumber: (u36::new(((data >> 12) & 68719476735).try_into().unwrap()).unwrap()), 
            ReservedForHardware: (u4::new(((data >> 48) & 15).try_into().unwrap()).unwrap()), 
            ReservedForSoftware: (u4::new(((data >> 52) & 15).try_into().unwrap()).unwrap()), 
            WsleAge: (u4::new(((data >> 56) & 15).try_into().unwrap()).unwrap()), 
            WsleProtection: (u3::new(((data >> 60) & 7).try_into().unwrap()).unwrap()), 
            NoExecute: (u1::new(((data >> 63) & 1).try_into().unwrap()).unwrap()) 
        }
    }

    pub fn is_present(&self) -> bool{
        return self.Valid.value() != 0
    }

}

impl PagingStruct for MMPTE_HARDWARE {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_present(&self) -> bool {
        return self.Valid.value() != 0
    }
    
    fn get_pfn(&self) -> u64{
        return self.PageFrameNumber.value() 
    } 

    fn is_executable(&self) -> bool {
        return self.NoExecute.value() == 0
    }

    fn get_state(&self) -> PageState {
        return PageState::HARDWARE
    }
}

#[derive(Debug)]
pub struct MMPTE_PROTOTYPE {
    pub Valid: u1,
    pub DemandFillProto: u1,
    pub HiberVerifyConverted: u1,
    pub ReadOnly: u1,
    pub SwizzleBit: u1,
    pub Protection: u5,
    pub Prototype: u1,
    pub Combined: u1,
    pub Unused1: u4,
    pub ProtoAddress: u48
}

impl MMPTE_PROTOTYPE {
    pub fn new (data: u64) -> Self {
        Self { 
            Valid: (u1::new((data & 1).try_into().unwrap()).unwrap()), 
            DemandFillProto: (u1::new(((data >> 1) & 1).try_into().unwrap()).unwrap()), 
            HiberVerifyConverted: (u1::new(((data >> 2) & 1).try_into().unwrap()).unwrap()), 
            ReadOnly: (u1::new(((data >> 3) & 1).try_into().unwrap()).unwrap()), 
            SwizzleBit: (u1::new(((data >> 4) & 1).try_into().unwrap()).unwrap()), 
            Protection: (u5::new(((data >> 5) & 31).try_into().unwrap()).unwrap()), 
            Prototype: (u1::new(((data >> 10) & 1).try_into().unwrap()).unwrap()), 
            Combined: (u1::new(((data >> 11) & 1).try_into().unwrap()).unwrap()), 
            Unused1: (u4::new(((data >> 12) & 15).try_into().unwrap()).unwrap()), 
            ProtoAddress: (u48::new(((data >> 16) & 281474976710655).try_into().unwrap()).unwrap()) 
        }
    }

    pub fn is_prototype(&self) -> bool {
        return self.Prototype.value() != 0
    }
}

impl PagingStruct for MMPTE_PROTOTYPE {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_present(&self) -> bool {
        return self.Valid.value() != 0
    }
    
    fn get_pfn(&self) -> u64{
        return 0
    } 

    fn is_executable(&self) -> bool {
        return false
    }
    
    fn get_state(&self) -> PageState {
        return PageState::PROTOTYPE
    }
}

#[derive(Debug)]
pub struct MMPTE_TRANSITION {
    pub Valid: u1,
    pub Write: u1,
    pub Spare: u1,
    pub IoTracker: u1,
    pub SwizzleBit: u1,
    pub Protection: u5,
    pub Prototype: u1,
    pub Transition: u1,
    pub PageFrameNumber: u36,
    pub Unused: u16
}

impl MMPTE_TRANSITION {
    pub fn new(data: u64) -> Self {
        Self { 
            Valid: (u1::new((data & 1).try_into().unwrap()).unwrap()), 
            Write: (u1::new(((data >> 1) & 1).try_into().unwrap()).unwrap()), 
            Spare: (u1::new(((data >> 2) & 1).try_into().unwrap()).unwrap()), 
            IoTracker: (u1::new(((data >> 3) & 1).try_into().unwrap()).unwrap()), 
            SwizzleBit: (u1::new(((data >> 4) & 1).try_into().unwrap()).unwrap()), 
            Protection: (u5::new(((data >> 9) & 31).try_into().unwrap()).unwrap()), 
            Prototype: (u1::new(((data >> 10) & 1).try_into().unwrap()).unwrap()), 
            Transition: (u1::new(((data >> 11) & 1).try_into().unwrap()).unwrap()), 
            PageFrameNumber: (u36::new(((data >> 12) & 68719476735).try_into().unwrap()).unwrap()), 
            Unused: (((data >> 48) & 65535).try_into().unwrap())
        }
    }   

    pub fn is_transition(&self) -> bool {
        return self.Transition.value() != 0
    } 
}

impl PagingStruct for MMPTE_TRANSITION {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_present(&self) -> bool {
        return self.Valid.value() != 0
    }
    
    fn get_pfn(&self) -> u64{
        return self.PageFrameNumber.value() 
    } 

    fn is_executable(&self) -> bool {
        return false
    }
    
    fn get_state(&self) -> PageState {
        return PageState::TRANSITION
    }
}

pub fn parse_pte(data: u64) -> BoxResult<Box<dyn PagingStruct>> {
    // Detect PTE state and return the correct object describing the PTE
    let hardware_state = MMPTE_HARDWARE::new(data);
    if hardware_state.is_present() {
        return Ok(Box::new(hardware_state));
    }

    let prototype_state = MMPTE_PROTOTYPE::new(data);
    if prototype_state.is_prototype() {
        return Ok(Box::new(prototype_state));
    }

    let transition_state = MMPTE_TRANSITION::new(data);
    if transition_state.is_transition() {
        return Ok(Box::new(transition_state));
    }

    return Err(Box::<dyn Error>::from("Paged out page"));
}

// pub fn deref_prototype_pte(pte: MMPTE_PROTOTYPE) -> BoxResult<Box<dyn PagingStruct>>{}
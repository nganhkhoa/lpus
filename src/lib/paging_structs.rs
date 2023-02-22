use std::convert::TryInto;

use bit_struct::*; 

// Ref: https://back.engineering/23/08/2020/
// Ref: https://blog.efiens.com/post/luibo/address-translation-revisited/

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

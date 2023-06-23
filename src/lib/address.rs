use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::rc::Rc;

// pub struct Object {
//     name: String,
//     address: Address
// }
//
// impl Object {
//     pub fn get<F>(&self, resolver: &F) -> u64
//         where F: Fn(u64) -> u64 {
//         // this function returns address of Object
//         self.address.get(resolver)
//     }
// }

pub struct Address {
    base: u64,
    pointer: Option<Rc<Address>>,
    offset: u64,
    // TODO: resolver
    // It would be nice to have an address resolver
    // Then implement Deref trait to call get()
    // resolver uses DriverState address decompose
    // lifetime issue occur
}

impl Address {
    pub fn from_base(base: u64) -> Self {
        Address {
            base: base,
            pointer: None,
            offset: 0,
        }
    }
    pub fn from_ptr(pointer: Address) -> Self {
        Address {
            base: 0,
            pointer: Some(Rc::new(pointer)),
            offset: 0,
        }
    }
    fn deref<F>(&self, resolver: &F) -> Address
    where
        F: Fn(u64) -> u64,
    {
        match &self.pointer {
            Some(p) => {
                let addr = p.deref(resolver);
                // println!("deref: {} -> {}; resolve: 0x{:x}", self, addr, addr.base + addr.offset);
                let base = if addr.base != 0 {
                    resolver(addr.base + addr.offset)
                } else {
                    0
                };
                Address {
                    base: base,
                    pointer: None,
                    offset: self.offset,
                }
            }
            None => Address {
                base: self.base,
                pointer: None,
                offset: self.offset,
            },
        }
    }
    pub fn get<F>(&self, resolver: &F) -> u64
    where
        F: Fn(u64) -> u64,
    {
        if self.pointer.is_some() {
            self.deref(resolver).get(resolver)
        } else if self.base == 0 {
            0
        } else {
            self.base + self.offset
        }
    }
    pub fn address(&self) -> u64 {
        self.base + self.offset
    }
    // pub fn to(&self, name: &str) -> Object {
    //     Object {
    //         name: name.to_string(),
    //         address: self.clone()
    //     }
    // }
}

impl Add<u64> for Address {
    type Output = Self;
    fn add(self, other: u64) -> Self {
        Self {
            base: self.base,
            pointer: self.pointer.map(|p| Rc::clone(&p)),
            offset: self.offset + other,
        }
    }
}

impl AddAssign<u64> for Address {
    fn add_assign(&mut self, other: u64) {
        *self = Self {
            base: self.base,
            pointer: self.pointer.clone(),
            offset: self.offset + other,
        }
    }
}

impl Sub<u64> for Address {
    type Output = Self;
    fn sub(self, other: u64) -> Self {
        Self {
            base: self.base,
            pointer: self.pointer.map(|p| Rc::clone(&p)),
            offset: self.offset - other,
        }
    }
}

impl SubAssign<u64> for Address {
    fn sub_assign(&mut self, other: u64) {
        *self = Self {
            base: self.base,
            pointer: self.pointer.clone(),
            offset: self.offset - other,
        }
    }
}

impl PartialEq for Address {
    fn eq(&self, other: &Self) -> bool {
        self.pointer.is_none()
            && other.pointer.is_none()
            && self.base == other.base
            && self.offset == other.offset
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Address) -> Option<Ordering> {
        if self.pointer.is_some() || other.pointer.is_some() {
            None
        } else {
            let this = self.base + self.offset;
            let that = other.base + other.offset;
            Some(this.cmp(&that))
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(p) = &self.pointer {
            write!(f, "*({}) + 0x{:x}", *p, self.offset)
        } else if self.offset != 0 {
            write!(f, "0x{:x} + 0x{:x}", self.base, self.offset)
        } else {
            write!(f, "0x{:x}", self.base)
        }
    }
}

impl Clone for Address {
    fn clone(&self) -> Self {
        Address {
            base: self.base,
            pointer: self.pointer.clone(),
            offset: self.offset,
        }
    }
}

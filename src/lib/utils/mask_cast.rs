pub trait MaskCast<T> {
    // Casting u64 to other primitive types, and vice versa
    // Use for bitmask casting inside struct field decomposing
    // It's basically std::convert::Into trait but Rust won't let me implement that for primitive type (FUCK)
    fn mask_cast_to(self) -> T;
    fn mask_cast_from(val: T) -> Self;
}

impl MaskCast<u64> for u8 {
    fn mask_cast_to(self) -> u64 {
        return self as u64;
    }
    fn mask_cast_from(val: u64) -> Self {
        return val as u8
    }
}

impl MaskCast<u64> for u16 {
    fn mask_cast_to(self) -> u64 {
        return self as u64;
    }
    fn mask_cast_from(val: u64) -> Self {
        return val as u16;
    }
}

impl MaskCast<u64> for u32 {
    fn mask_cast_to(self) -> u64 {
        return self as u64;
    }

    fn mask_cast_from(val: u64) -> Self {
        return val as u32;
    }
}

impl MaskCast<u64> for u64 {
    fn mask_cast_from(val: u64) -> Self {
        return val;
    }
    fn mask_cast_to(self) -> u64 {
        return self
    }
}

pub fn get_bit_mask_handler(pos: u64, len: u64)-> Box<dyn Fn(u64) -> u64> {
    // Generate a function to get "len" bit, starting at posistion "pos" of a number
    Box::new(move |val: u64| -> u64 {
        // Work-around rust's overflow check when compile
        (val >> pos) & (((1 as u128) << len) - 1) as u64
    })
}
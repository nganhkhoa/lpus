pub mod mask_cast;

pub fn get_bit_mask_handler(pos: u64, len: u64)-> Box<dyn Fn(u64) -> u64> {
    // Generate a function to get "len" bit, starting at posistion "pos" of a number
    Box::new(move |val: u64| -> u64 {(val >> pos) & ((1 << len) - 1)})
}
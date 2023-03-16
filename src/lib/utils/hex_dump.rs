extern crate hexplay;

use hexplay::HexViewBuilder;

pub fn print_hex_dump(data: &Vec<u8>, start_address: u64) {
    let view = HexViewBuilder::new(data)
    .address_offset(start_address)
    .row_width(16)
    .finish();

    println!("{}", view);
}
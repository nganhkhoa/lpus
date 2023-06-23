extern crate hexplay;

use hexplay::HexViewBuilder;

pub fn trim_null_bytes(x: &Vec<u8>) -> Vec<u8> {
    let from = match x.iter().position(|x| *x != 0) {
        Some(i) => i,
        None => return x[0..0].to_vec(),
    };
    let to = x.iter().rposition(|x| *x != 0).unwrap();
    x[0..=to].to_vec()
}

pub fn trim_null_bytes_right(x: &Vec<u8>) -> Vec<u8> {
    // let from = match x.iter().position(|x| *x != 0) {
    //     Some(i) => i,
    //     None => return x[0..0].to_vec(),
    // };
    match x.iter().rposition(|x| *x != 0) {
           Some(i) => return x[0..=i].to_vec(),
           None => return x[0..0].to_vec()
    };
}

pub fn print_hex_dump(data: &Vec<u8>, start_address: u64) {
    let trimmed_array = trim_null_bytes_right(data);

    let view = HexViewBuilder::new(&trimmed_array)
    .address_offset(start_address as usize)
    .row_width(16)
    .finish();
    println!("{}", view);
}
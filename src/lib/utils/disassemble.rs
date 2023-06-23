extern crate capstone;
use capstone::prelude::*;

use crate::utils::hex_dump::trim_null_bytes_right;

pub fn disassemble_array_x64(data: &Vec<u8>, start_address: u64) {
    let trimmed_array = trim_null_bytes_right(data);

    let cs = Capstone::new()
    .x86()
    .mode(arch::x86::ArchMode::Mode64)
    .syntax(arch::x86::ArchSyntax::Intel)
    .detail(false)
    .build()
    .expect("Failed to create Capstone object");

    let instructions = cs.disasm_all(data, start_address)
        .expect("Failed to disassemble");

    for i in instructions.as_ref() {
        println!("{}", i);
    }

}
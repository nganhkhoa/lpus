extern crate vergen;

use vergen::{generate_cargo_keys, ConstantsFlags};

fn main() {
    let flags = ConstantsFlags::all();
    generate_cargo_keys(flags).expect("Unable to generate the cargo keys!");
}

use lpus::pdb_store::*;
use lpus::address::*;
fn main() {
    let pdb = parse_pdb().unwrap();
    // println!("PDB: {:?}", pdb.structs.get("_TEB_ACTIVE_FRAME_CONTEXT"));
    println!("PDB: {:?}", pdb.structs.get("_HARDWARE_PTE"));

    // println!("{}", pdb.decompose(&Address::from_base(0), "_EPROCESS.Peb").unwrap().0);
    println!("{}", pdb.decompose(&Address::from_base(0), "_HARDWARE_PTE.PageFrameNumber").unwrap().0);
}

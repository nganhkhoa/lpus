mod pdb_store;
mod windows;

fn main() {
    let store = pdb_store::parse_pdb();
    store.print_default_information();

    let mut windows_ffi = windows::WindowsFFI::new();
    windows_ffi.print_version();

    println!("NtLoadDriver()   -> 0x{:x}", windows_ffi.load_driver());
    println!("NtUnloadDriver() -> 0x{:x}", windows_ffi.unload_driver());
}

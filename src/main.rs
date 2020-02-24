mod pdb_store;
mod windows;

fn main() {
    let store = pdb_store::parse_pdb();
    store.print_default_information();

    // for windows admin require
    // https://github.com/nabijaczleweli/rust-embed-resource
    let mut windows_ffi = windows::WindowsFFI::new();
    windows_ffi.print_version();

    println!("NtLoadDriver()   -> 0x{:x}", windows_ffi.load_driver());

    windows_ffi.device_io(0x900);

    println!("NtUnloadDriver() -> 0x{:x}", windows_ffi.unload_driver());
}

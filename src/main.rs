extern crate reqwest;
use std::io::{Write};
use std::path::Path;
use std::net::TcpListener;
use std::thread;


mod pdb_store;
mod windows;

fn main() {
    if !Path::new(pdb_store::PDBNAME).exists() {
        pdb_store::download_pdb();
    }
    let store = pdb_store::parse_pdb();
    store.print_default_information();

    // match store.get_offset("MiState") {
    //     Some(offset) => println!("0x{:x} MiState", offset),
    //     None => {}
    // };
    // match store.get_offset("_MI_HARDWARE_STATE.SystemNodeNonPagedPool") {
    //     Some(offset) => println!("0x{:x} _MI_HARDWARE_STATE.SystemNodeNonPagedPool", offset),
    //     None => {}
    // };
    // match store.addr_decompose(0xfffff8005d44f200, "_MI_SYSTEM_INFORMATION.Hardware.SystemNodeNonPagedPool") {
    //     Ok(offset) =>
    //         println!("0x{:x} == ((_MI_SYSTEM_INFORMATION)0xfffff8005d44f200).Hardware.SystemNodeNonPagedPool", offset),
    //     Err(msg) =>  println!("{}", msg)
    // };

    let mut windows_ffi = windows::WindowsFFI::new();
    windows_ffi.print_version();

    println!("NtLoadDriver()   -> 0x{:x}", windows_ffi.load_driver());
    println!("NtUnloadDriver() -> 0x{:x}", windows_ffi.unload_driver());

    // let listener = TcpListener::bind("127.0.0.1:8989").expect("Cannot bind to port 8989");
    // println!("listening started, ready to accept");
    // for stream in listener.incoming() {
    //     thread::spawn(|| {
    //         println!("Connection received");
    //         let mut stream = stream.unwrap();
    //         stream.write(b"Hello World\r\n").unwrap();
    //     });
    // }
}

use clap::{App, Arg, SubCommand};
use lpus::{driver_state::DriverState, scan_eprocess};
use std::error::Error;

#[macro_use]
extern crate prettytable;
use prettytable::{Cell, Row, Table};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Translate virtual address")
    .arg(
        Arg::with_name("addr")
            .long("addr")
            .short("a")
            .multiple(false)
            .help("Specify the virtual address to translate")
            .takes_value(true)
            .required(true)
    )
    .get_matches();


    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!(
            "Windows version {:?} is not supported",
            driver.windows_ffi.short_version
        )
            .into());
    }
    if matches.is_present("addr"){
        println!("NtLoadDriver()   -> 0x{:x}", driver.startup());
        let addr: u64 = matches.value_of("addr").unwrap().parse::<u64>().unwrap();
        let content: u64 = driver.deref_physical_addr(addr);
        println!("Result: Got 0x{:x} from address 0x{:x}", content, addr);
        println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    }
    Ok(())
}

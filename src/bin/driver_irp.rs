use std::error::Error;

use parse_int::parse;
use rustyline::error::ReadlineError;
use rustyline::Editor;

use lpus::{driver_state::DriverState, get_irp_name, scan_driver, scan_kernel_module};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!(
            "Windows version {:?} is not supported",
            driver.windows_ffi.short_version
        )
        .into());
    }
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    let drivers = scan_driver(&driver).unwrap_or(Vec::new());
    let kmods = scan_kernel_module(&driver).unwrap_or(Vec::new());

    for d in drivers.iter() {
        println!("{} {}", d["device"], d["address"]);
    }

    let mut rl = Editor::<()>::new();
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                for d in drivers.iter() {
                    if d["address"].as_str().unwrap_or("") == line {
                        println!("{:#}", d);
                        for (idx, addr_) in d["major_function"]
                            .as_array()
                            .unwrap_or(&Vec::new())
                            .iter()
                            .enumerate()
                        {
                            for kmod in kmods.iter() {
                                let addr: u64 =
                                    addr_.as_str().and_then(|x| parse(x).ok()).unwrap_or(0);
                                let base: u64 = kmod["dllbase"]
                                    .as_str()
                                    .and_then(|x| parse(x).ok())
                                    .unwrap_or(0);
                                let size: u64 = kmod["size"]
                                    .as_str()
                                    .and_then(|x| parse(x).ok())
                                    .unwrap_or(0);
                                if addr > base && addr < base + size {
                                    println!(
                                        "{} 0x{:x} {}",
                                        get_irp_name(idx),
                                        addr,
                                        kmod["BaseName"]
                                    );
                                    break;
                                }
                            }
                        }
                        break;
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

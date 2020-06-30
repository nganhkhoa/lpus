use std::error::Error;

use parse_int::parse;

use lpus::{
    driver_state::{DriverState},
    traverse_loadedmodulelist,
    traverse_unloadeddrivers
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!("Windows version {:?} is not supported", driver.windows_ffi.short_version).into());
    }
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    let loaded = traverse_loadedmodulelist(&driver).unwrap_or(Vec::new());
    let unloaded = traverse_unloadeddrivers(&driver).unwrap_or(Vec::new());

    // TODO: move to another place
    // From Vol3 SSDT scan
    // https://github.com/volatilityfoundation/volatility3/blob/master/volatility/framework/plugins/windows/ssdt.py
    let ntosbase = driver.get_kernel_base();
    let servicetable = ntosbase.clone() + driver.pdb_store.get_offset_r("KiServiceTable")?;
    let servicelimit_ptr = ntosbase.clone() + driver.pdb_store.get_offset_r("KiServiceLimit")?;

    let servicelimit = driver.deref_addr_new::<u32>(servicelimit_ptr.address()) as u64;
    let ssdt: Vec<u64> = driver.deref_array::<u32>(&servicetable, servicelimit)
                         .iter().map(|entry| {
                            servicetable.address() + ((entry >> 4) as u64)
                         }).collect();

    for r in loaded.iter() {
        println!("{:#}", r.to_string());
    }
    println!("=============================================");
    for r in unloaded.iter() {
        println!("{:#}", r.to_string());
    }
    println!("=============================================");
    for func in ssdt {
        for r in loaded.iter() {
            let base = r["dllbase"].as_str().and_then(|b| parse::<u64>(b).ok()).unwrap_or(0);
            let size = r["size"].as_str().and_then(|s| parse::<u64>(s).ok()).unwrap_or(0);

            if func > base && func < base + size {
                let offset = func - ntosbase.address();
                let funcname: String = {
                    let mut n = "".to_string();
                    for (name, o) in driver.pdb_store.symbols.iter() {
                        if *o == offset {
                            n = name.clone();
                        }
                    }
                    if n == "" {
                        "(??)".to_string()
                    }
                    else {
                        n
                    }
                };
                println!("SSDT 0x{:x} {}!{}", func, r["BaseName"], funcname);
                break; // next func
            }
        }
        // TODO: If not found, search other list
    }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

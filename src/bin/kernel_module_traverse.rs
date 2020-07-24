use std::error::Error;

use parse_int::parse;

use lpus::{
    driver_state::DriverState, ssdt_table, traverse_loadedmodulelist, traverse_unloadeddrivers,
};

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

    let loaded = traverse_loadedmodulelist(&driver).unwrap_or(Vec::new());
    let unloaded = traverse_unloadeddrivers(&driver).unwrap_or(Vec::new());
    let ssdt = ssdt_table(&driver)?;
    let ntosbase = driver.get_kernel_base();

    // for r in loaded.iter() {
    //     println!("{:#}", r.to_string());
    // }
    println!("=============================================");
    for r in unloaded.iter() {
        println!("{:#}", r);
    }
    println!("=============================================");
    for (idx, func) in ssdt.iter().enumerate() {
        println!("SSDT [{}]\t0x{:x}", idx, func);
        let owner = loaded.iter().find_map(|r| {
            let base = r["dllbase"]
                .as_str()
                .and_then(|b| parse::<u64>(b).ok())
                .unwrap_or(0);
            let size = r["size"]
                .as_str()
                .and_then(|s| parse::<u64>(s).ok())
                .unwrap_or(0);

            if *func > base && *func < base + size {
                let module = r["BaseName"].as_str().unwrap();
                Some(module)
            }
            else {
                None
            }
        });
        if owner == Some("ntoskrnl.exe") {
            let offset = func - ntosbase.address();
            let funcname: String = {
                driver.pdb_store.symbols.iter().find_map(|(name, o)| {
                    if o.clone() == offset {
                        Some(name.clone())
                    }
                    else {
                        None
                    }
                }).unwrap_or("(??)".to_string())
            };
            println!("\towned by nt!{}", funcname);
        }
        else if let Some(owner_) = owner {
            println!("\\thooked by {}", owner_);
        }
        else {
            println!("\tmissing owner");
        }
    }

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

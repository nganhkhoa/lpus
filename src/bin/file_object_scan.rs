use std::error::Error;

use lpus::{
    driver_state::{DriverState}
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    driver.scan_pool(b"File", "_FILE_OBJECT", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let fob_size = driver.pdb_store.get_offset_r("_FILE_OBJECT.struct_size")?;
        let valid_end = (pool_addr.clone() + chunk_size) - fob_size;
        let mut try_ptr = data_addr;

        while try_ptr <= valid_end {
            let ftype: u16 = driver.decompose(&try_ptr, "_FILE_OBJECT.Type")?;
            let size: u16 = driver.decompose(&try_ptr, "_FILE_OBJECT.Size")?;
            if (size as u64) == fob_size && ftype == 5u16 {
                break;
            }
            try_ptr += 0x4;        // search exhaustively
        }
        if try_ptr > valid_end {
            return Ok(false);
        }

        let fob_addr = &try_ptr;
        let read_ok: u8 = driver.decompose(fob_addr, "_FILE_OBJECT.ReadAccess")?;
        let unicode_str_ptr = driver.address_of(fob_addr, "_FILE_OBJECT.FileName")?;

        println!("pool: {} | file object: {}", pool_addr, fob_addr);
        if read_ok == 0 {
            println!("      [NOT READABLE]");
        }
        else if let Ok(filename) = driver.get_unicode_string(unicode_str_ptr, true) {
            println!("      {}", filename);
        }
        else {
            println!("      [NOT A VALID _UNICODE_STRING]");
        }
        Ok(true)
    })?;

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}



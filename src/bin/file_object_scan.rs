use std::error::Error;

use lpus::{
    driver_state::{DriverState}
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    driver.scan_pool(b"File", |pool_addr, header, data_addr| {
        let chunk_size = (header[2] as u64) * 16u64;

        let fob_size = driver.pdb_store.get_offset_r("_FILE_OBJECT.struct_size")?;
        let fob_size_offset = driver.pdb_store.get_offset_r("_FILE_OBJECT.Size")?;
        let fob_filename_offset = driver.pdb_store.get_offset_r("_FILE_OBJECT.FileName")?;

        let valid_end = (pool_addr + chunk_size) - fob_size;
        let mut try_ptr = data_addr;

        let mut ftype = 0u16;
        let mut size = 0u16;
        while try_ptr <= valid_end {
            driver.deref_addr(try_ptr, &mut ftype);
            driver.deref_addr(try_ptr + fob_size_offset, &mut size);
            if (size as u64) == fob_size && ftype == 5u16 {
                break;
            }
            try_ptr += 0x4;        // search exhaustively
        }
        if try_ptr > valid_end {
            return Ok(false);
        }
        let fob_addr = try_ptr;
        // println!("pool: 0x{:x} | file object: 0x{:x} | offsetby: {}", pool_addr, fob_addr, fob_addr - pool_addr);
        if let Ok(filename) = driver.get_unicode_string(fob_addr + fob_filename_offset) {
            println!("pool: 0x{:x} | file object: 0x{:x} | offsetby: {} | {}",
                    pool_addr, fob_addr, fob_addr - pool_addr, filename);
            return Ok(true);
        }
        Ok(false)
    })?;

    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}



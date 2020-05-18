# LPUS (A live pool-tag scanning solution)

This is the frontend to the live pool tag scanning solution, the backend is a driver (which is now closed source).

## How this works

In simple way, we use PDB files to get the global variable offsets and structure definitions.
The backend finds the kernel base and use these values to calculate the nonpaged-pool range.
A more detailed report is in [nonpaged-pool-range.md](nonpaged-pool-range.md)
The frontend calls the backend to scan for a specific tag.

## How to use

Example is [here](./src/bin/eprocess_scan.rs).

```rust
use lpus::{
    driver_state::{DriverState}
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut driver = DriverState::new();
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());
    driver.scan_pool(b"Tag ", |pool_addr, header, data_addr| {
    })?;
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
}
```

The closure is a mutable closure, so you can just put a vector and saves the result.
The function signature for the closure is: `FnMut(u64, &[u8], u64) -> Result<bool, std::error::Error>`
Parsing the struct data is up to you.
You can use `driver.deref_addr(addr, &value)` to dereference an address in kernel space
and `driver.pdb_store.get_offset_r("offset")?` to get an offset from PDB file.


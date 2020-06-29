# LPUS (A live pool-tag scanning solution)

This is the frontend to the live pool tag scanning solution, the backend is a
driver (which is now closed source).

Works on Windows 7 and above (Vista not tested, but 7 ok and 10 ok), and on x64
systems only. (I hardcoded the address as u64 so only 64 systems should run this).

> The binary is runable, without crashing. But I still need to add some
manual instructions on referencing the structs and offset on some places.
> Windows 10, versions 2018, 2019 and 2020 is tested and works.

Windows XP is not supported: Windows XP Win32Api is missing here and there.

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
    driver.scan_pool(b"Tag ", "_STRUCT_NAME", |pool_addr, header, data_addr| {
    })?;
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
}
```

The closure is a mutable closure, so you can just put a vector and saves the result.
The function signature for the closure is: `FnMut(u64, &[u8], u64) -> Result<bool, std::error::Error>`
Parsing the struct data is up to you.
You can use `driver.deref_addr(addr, &value)` to dereference an address in kernel space
and `driver.pdb_store.get_offset_r("offset")?` to get an offset from PDB file.

We also have a set of functions for scanning a specific tag/object.

- `pub fn scan_eprocess(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn scan_file(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn scan_ethread(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn scan_mutant(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn scan_driver(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn scan_kernel_module(driver: &DriverState) -> BoxResult<Vec<Value>>`

And a list traversing the kernel object:

- `pub fn traverse_loadedmodulelist(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn traverse_activehead(driver: &DriverState) -> BoxResult<Vec<Value>>`
- missing symbols `pub fn traverse_afdendpoint(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn traverse_kiprocesslist(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn traverse_handletable(driver: &DriverState) -> BoxResult<Vec<Value>>`
- `pub fn traverse_unloadeddrivers(driver: &DriverState) -> BoxResult<Vec<Value>>`

## Things to note

Right now, we only have one symbol file of ntoskrnl.exe. While we may need more
symbols, kernel32.sys, win32k.sys, tcpis.sys...  This will be a future update
where symbols are combined into one big `HashMap` but still retain the module.  I
haven't tested the debug symbols of others binary, I wonder if the PDB file even
exists.

The pdb file is not restricted in ntoskrnl.exe, I might need to split to a
smaller module or such.

Also the symbols list is parsed directly from the PDB file, but some structs
(like the callback routine members or network structs) are missing. Right now a
simple hardcoded to add in a struct member is used, but it would break if the
OS running have a different layout. 

The HashMap of symbols/struct is now using string and u32 to store member
offset and types, this should be changed into something that would be type-safe
and more functional.

I also follow a few Volatility implementation on Rootkit, The art of Memory
forensics Chapter 13.  Scanning in Windows 10 yields promising result, though I
haven't tested on any malware to see if we can have the "same" result.

At the pace of development, I seperate the binary to functionalities for
testing, I would add a CLI and a REPL.

One last thing, the backend doesn't have any check on address referencing, so
one may get a blue screen, eventhough I tried to avoid it, I'm not 100% sure it
would not crash the system.

## Future works

- [ ] An interactive repl (1)
- [ ] More kernel modules symbols (2)
- [ ] Implementation of more technique (reference Volatility here)
- [ ] Quick and easy way to add manual struct, symbols (3)

(1) This is quite hard to work out, because we have to make the *types* works.
The currently chosen repl is based on Lisp, because lisp is cool.  If the repl
is online, we can combine everything into one binary.

(2) We may need to download it all and combine to one `HashMap`, with their
types as a specific struct. (Try to avoid string).

(3) Have no idea on this.

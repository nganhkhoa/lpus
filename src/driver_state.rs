use std::default::Default;
use std::clone::Clone;
use std::error::Error;
// use std::io::{Error, ErrorKind};
use std::ffi::c_void;
use std::mem::{size_of_val, size_of};

use winapi::shared::ntdef::{NTSTATUS};
use winapi::shared::minwindef::{DWORD};
use winapi::um::winioctl::{
    CTL_CODE, FILE_ANY_ACCESS,
    METHOD_IN_DIRECT, METHOD_OUT_DIRECT, /* METHOD_BUFFERED, */ METHOD_NEITHER
};

use crate::address::Address;
use crate::pdb_store::{PdbStore, parse_pdb};
use crate::windows::{WindowsFFI, WindowsVersion};
use crate::ioctl_protocol::{
    InputData, OffsetData, DerefAddr, ScanPoolData, /* HideProcess, */
    /* OutputData, */ Nothing
};

type BoxResult<T> = Result<T, Box<dyn Error>>;

const SIOCTL_TYPE: DWORD = 40000;

pub fn to_epoch(filetime: u64) -> u64 {
    let windows_epoch_diff: u64 = 11644473600000 * 10000;
    if filetime < windows_epoch_diff {
        return 0;
    }
    let process_time_epoch: u64 = (filetime - windows_epoch_diff) / 10000;
    process_time_epoch
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum DriverAction {
    SetupOffset,
    GetKernelBase,
    ScanPsActiveHead,
    ScanPool,
    ScanPoolRemote,
    DereferenceAddress,
    HideProcess
}

impl DriverAction {
    pub fn get_code(&self) -> DWORD {
        match self {
            DriverAction::SetupOffset => CTL_CODE(SIOCTL_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS),
            DriverAction::GetKernelBase => CTL_CODE(SIOCTL_TYPE, 0x901, METHOD_OUT_DIRECT, FILE_ANY_ACCESS),
            DriverAction::ScanPsActiveHead => CTL_CODE(SIOCTL_TYPE, 0x902, METHOD_NEITHER, FILE_ANY_ACCESS),
            DriverAction::ScanPool => CTL_CODE(SIOCTL_TYPE, 0x903, METHOD_IN_DIRECT, FILE_ANY_ACCESS),
            DriverAction::ScanPoolRemote => CTL_CODE(SIOCTL_TYPE, 0x904, METHOD_IN_DIRECT, FILE_ANY_ACCESS),
            DriverAction::DereferenceAddress => CTL_CODE(SIOCTL_TYPE, 0xA00, METHOD_OUT_DIRECT, FILE_ANY_ACCESS),
            DriverAction::HideProcess => CTL_CODE(SIOCTL_TYPE, 0xA01, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
        }
    }
}

#[derive(Debug)]
pub struct EprocessPoolChunk {
    pub pool_addr: u64,
    pub eprocess_addr: u64,
    pub eprocess_name: String,
    pub create_time: u64,
    pub exit_time: u64
}

impl PartialEq for EprocessPoolChunk {
    fn eq(&self, other: &Self) -> bool {
        self.eprocess_addr == other.eprocess_addr
    }
}

#[allow(dead_code)]
pub struct DriverState {
    // TODO: Make private, only call methods of DriverState
    pub pdb_store: PdbStore,
    pub windows_ffi: WindowsFFI,
}

impl DriverState {
    pub fn new() -> Self {
        Self {
            pdb_store: parse_pdb().expect("Cannot get PDB file"),
            windows_ffi: WindowsFFI::new()
        }
    }

    pub fn startup(&mut self) -> NTSTATUS {
        let s = self.windows_ffi.load_driver();
        let mut input = InputData {
            offset_value: OffsetData::new(&self.pdb_store, self.windows_ffi.short_version)
        };
        self.windows_ffi.device_io(DriverAction::SetupOffset.get_code(),
                                   &mut input, &mut Nothing);
        s
    }

    pub fn shutdown(&self) -> NTSTATUS {
        self.windows_ffi.unload_driver()
    }

    pub fn get_kernel_base(&self) -> Address {
        let mut ntosbase = 0u64;
        self.windows_ffi.device_io(DriverAction::GetKernelBase.get_code(),
                                   &mut Nothing, &mut ntosbase);
        Address::from_base(ntosbase)
    }

    // pub fn scan_active_head(&self) -> BoxResult<Vec<EprocessPoolChunk>> {
    //     let ntosbase = self.get_kernel_base();
    //     let ps_active_head = ntosbase + self.pdb_store.get_offset_r("PsActiveProcessHead")?;
    //     let flink_offset = self.pdb_store.get_offset_r("_LIST_ENTRY.Flink")?;
    //     let eprocess_link_offset = self.pdb_store.get_offset_r("_EPROCESS.ActiveProcessLinks")?;
    //     let eprocess_name_offset = self.pdb_store.get_offset_r("_EPROCESS.ImageFileName")?;
    //
    //     let mut ptr = ps_active_head;
    //     self.deref_addr((ptr + flink_offset).get(), &mut ptr);
    //
    //     let mut result: Vec<EprocessPoolChunk> = Vec::new();
    //     while ptr != ps_active_head {
    //         let mut image_name = [0u8; 15];
    //         let eprocess = ptr - eprocess_link_offset;
    //         self.deref_addr(eprocess + eprocess_name_offset, &mut image_name);
    //         match std::str::from_utf8(&image_name) {
    //             Ok(n) => {
    //                 result.push(EprocessPoolChunk {
    //                     pool_addr: 0,
    //                     eprocess_addr: eprocess,
    //                     eprocess_name: n.to_string()
    //                                     .trim_end_matches(char::from(0))
    //                                     .to_string(),
    //                     create_time: 0,
    //                     exit_time: 0
    //
    //                 });
    //             },
    //             _ => {}
    //         };
    //         self.deref_addr(ptr + flink_offset, &mut ptr);
    //     }
    //     Ok(result)
    // }

    pub fn scan_pool<F>(&self, tag: &[u8; 4], expected_struct: &str, mut handler: F) -> BoxResult<bool>
                        where F: FnMut(Address, &[u8], Address) -> BoxResult<bool>
                        // F(Pool Address, Pool Header Data, Pool Data Address)
                        // TODO: Pool Header as a real struct
    {
        // TODO: make generator, in hold: https://github.com/rust-lang/rust/issues/43122
        // Making this function a generator will turn the call to a for loop
        // https://docs.rs/gen-iter/0.2.0/gen_iter/
        // >> More flexibility in code
        let pool_header_size = self.pdb_store.get_offset_r("_POOL_HEADER.struct_size")?;
        let minimum_block_size = self.pdb_store.get_offset_r(&format!("{}.struct_size", expected_struct))?
                               + pool_header_size;
        let code = DriverAction::ScanPoolRemote.get_code();
        let ntosbase = self.get_kernel_base();
        let [start_address, end_address] = self.get_nonpaged_range(&ntosbase)?;

        println!("kernel base: {}; non-paged pool (start, end): ({}, {})", ntosbase, start_address, end_address);

        let mut ptr = start_address;
        while ptr < end_address {
            let mut next_found = 0u64;
            let mut input = InputData {
                scan_range: ScanPoolData::new(&[ptr.address(), end_address.address()], tag)
            };
            self.windows_ffi.device_io(code, &mut input, &mut next_found);
            ptr = Address::from_base(next_found);
            if ptr >= end_address {
                break;
            }

            let pool_addr = Address::from_base(ptr.address());
            let header: Vec<u8> = self.deref_array(&pool_addr, pool_header_size);
            let chunk_size = (header[2] as u64) * 16u64;

            if pool_addr.address() + chunk_size > end_address.address() {
                // the chunk surpasses the non page pool range
                break;
            }

            // automatically reject bad chunk
            if chunk_size < minimum_block_size {
                ptr += 0x4;
                continue;
            }

            let data_addr = Address::from_base(pool_addr.address() + pool_header_size);

            let success = handler(pool_addr, &header, data_addr)?;
            if success {
                ptr += chunk_size; /* skip this chunk */
            }
            else {
                ptr += 0x4; /* search next */
            }
        }
        Ok(true)
    }

    pub fn address_of(&self, addr: &Address, name: &str) -> BoxResult<u64> {
        let resolver = |p| { self.deref_addr_new(p) };
        let r = self.pdb_store.decompose(&addr, &name)?;
        Ok(r.get(&resolver))
    }

    pub fn decompose<T: Default>(&self, addr: &Address, name: &str) -> BoxResult<T> {
        // interface to pdb_store.decompose
        let resolver = |p| { self.deref_addr_new(p) };
        let r: T = self.deref_addr_new(self.pdb_store.decompose(&addr, &name)?.get(&resolver));
        Ok(r)
    }

    pub fn decompose_array<T: Default + Clone>(&self, addr: &Address, name: &str, len: u64) -> BoxResult<Vec<T>> {
        // interface to pdb_store.decompose for array
        let r: Vec<T> = self.deref_array(&self.pdb_store.decompose(&addr, &name)?, len);
        Ok(r)
    }

    pub fn deref_addr_new<T: Default>(&self, addr: u64) -> T {
        let mut r: T = Default::default();
        if addr != 0 {
            self.deref_addr(addr, &mut r);
        }
        r
    }

    pub fn deref_array<T: Default + Clone>(&self, addr: &Address, len: u64) -> Vec<T> {
        let resolver = |p| { self.deref_addr_new(p) };
        let mut r: Vec<T> = vec![Default::default(); len as usize];
        let size_in_byte = (len as usize) * size_of::<T>();
        self.deref_addr_ptr(addr.get(&resolver), r.as_mut_ptr(), size_in_byte as u64);
        r
    }

    // #[deprecated(note="use deref_addr_new<T>")]
    pub fn deref_addr<T>(&self, addr: u64, outbuf: &mut T) {
        let code = DriverAction::DereferenceAddress.get_code();
        let size: usize = size_of_val(outbuf);
        let mut input = InputData {
            deref_addr: DerefAddr {
                addr,
                size: size as u64
            }
        };
        self.windows_ffi.device_io(code, &mut input, outbuf);
    }

    // #[deprecated(note="use deref_array<T>")]
    pub fn deref_addr_ptr<T>(&self, addr: u64, outptr: *mut T, output_len_as_byte: u64) {
        let code = DriverAction::DereferenceAddress.get_code();
        let mut input = InputData {
            deref_addr: DerefAddr {
                addr,
                size: output_len_as_byte
            }
        };
        self.windows_ffi.device_io_raw(code,
                                       &mut input as *mut _ as *mut c_void, size_of_val(&input) as DWORD,
                                       outptr as *mut c_void, output_len_as_byte as DWORD);
    }

    pub fn get_unicode_string(&self, unicode_str_addr: u64) -> BoxResult<String> {
        if unicode_str_addr == 0 {
            return Err("Not a valid address".into());
        }

        let mut strlen = 0u16;
        let mut capacity = 0u16;
        let mut bufaddr = 0u64;
        let buffer_ptr = unicode_str_addr + self.pdb_store.get_offset_r("_UNICODE_STRING.Buffer")?;
        let capacity_addr  = unicode_str_addr + self.pdb_store.get_offset_r("_UNICODE_STRING.MaximumLength")?;

        self.deref_addr(unicode_str_addr, &mut strlen);
        self.deref_addr(capacity_addr, &mut capacity);
        self.deref_addr(buffer_ptr, &mut bufaddr);

        if bufaddr == 0 || strlen > capacity || strlen == 0 || strlen % 2 != 0 {
            return Err("Unicode string is empty".into());
        }

        let mut buf = vec![0u16; (strlen / 2) as usize];
        self.deref_addr_ptr(bufaddr, buf.as_mut_ptr(), strlen as u64);
        // TODO: BUG with deref_array, len is wrong,
        // >> the size of vector is strlen / 2
        // >> the size to dereference is strlen
        // XXX: use Vec<u8> and turn to Vec<u16>
        // let buf: Vec<u16> = self.deref_array(&Address::from_base(bufaddr), (strlen / 2) as u64);

        Ok(String::from_utf16(&buf)?)
    }

    pub fn get_nonpaged_range(&self, ntosbase: &Address) -> BoxResult<[Address; 2]> {
        // TODO: Add support for other Windows version here
        match self.windows_ffi.short_version {
            WindowsVersion::Windows10FastRing => {
                let mistate = ntosbase.clone() + self.pdb_store.get_offset_r("MiState")?;
                let path_first_va: String = vec![
                    "_MI_SYSTEM_INFORMATION",
                    "Hardware",
                    "SystemNodeNonPagedPool",
                    "NonPagedPoolFirstVa"
                ].join(".");
                let path_last_va: String = vec![
                    "_MI_SYSTEM_INFORMATION",
                    "Hardware",
                    "SystemNodeNonPagedPool",
                    "NonPagedPoolLastVa"
                ].join(".");
                let first_va = Address::from_base(self.decompose(&mistate, &path_first_va)?);
                let last_va = Address::from_base(self.decompose(&mistate, &path_last_va)?);
                Ok([first_va, last_va])
            },
            WindowsVersion::Windows10_2019 |
            WindowsVersion::Windows10_2018 => {
                let mistate = ntosbase.clone() + self.pdb_store.get_offset_r("MiState")?;
                let path_first_va: String = vec![
                    "_MI_SYSTEM_INFORMATION",
                    "Hardware",
                    "SystemNodeInformation",
                    "NonPagedPoolFirstVa"
                ].join(".");
                let path_last_va: String = vec![
                    "_MI_SYSTEM_INFORMATION",
                    "Hardware",
                    "SystemNodeInformation",
                    "NonPagedPoolLastVa"
                ].join(".");
                let first_va = Address::from_base(self.decompose(&mistate, &path_first_va)?);
                let last_va = Address::from_base(self.decompose(&mistate, &path_last_va)?);
                Ok([first_va, last_va])
            },
            _ => {
                Err("Windows version for nonpaged pool algorithm is not implemented".into())
            }
        }
    }

}

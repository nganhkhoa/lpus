use std::error::Error;
// use std::io::{Error, ErrorKind};
use std::ffi::c_void;
use std::mem::{size_of_val};

use winapi::shared::ntdef::{NTSTATUS};
use winapi::shared::minwindef::{DWORD};
use winapi::um::winioctl::{
    CTL_CODE, FILE_ANY_ACCESS,
    METHOD_IN_DIRECT, METHOD_OUT_DIRECT, /* METHOD_BUFFERED, */ METHOD_NEITHER
};

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

    pub fn get_kernel_base(&self) -> u64 {
        let mut ntosbase = 0u64;
        self.windows_ffi.device_io(DriverAction::GetKernelBase.get_code(),
                                   &mut Nothing, &mut ntosbase);
        // println!("ntosbase: 0x{:x}", self.ntosbase);
        ntosbase
    }

    pub fn scan_active_head(&self) -> BoxResult<Vec<EprocessPoolChunk>> {
        let ntosbase = self.get_kernel_base();
        let ps_active_head = ntosbase + self.pdb_store.get_offset_r("PsActiveProcessHead")?;
        let flink_offset = self.pdb_store.get_offset_r("_LIST_ENTRY.Flink")?;
        let eprocess_link_offset = self.pdb_store.get_offset_r("_EPROCESS.ActiveProcessLinks")?;
        let eprocess_name_offset = self.pdb_store.get_offset_r("_EPROCESS.ImageFileName")?;

        let mut ptr = ps_active_head;
        self.deref_addr(ptr + flink_offset, &mut ptr);

        let mut result: Vec<EprocessPoolChunk> = Vec::new();
        while ptr != ps_active_head {
            let mut image_name = [0u8; 15];
            let eprocess = ptr - eprocess_link_offset;
            self.deref_addr(eprocess + eprocess_name_offset, &mut image_name);
            match std::str::from_utf8(&image_name) {
                Ok(n) => {
                    result.push(EprocessPoolChunk {
                        pool_addr: 0,
                        eprocess_addr: eprocess,
                        eprocess_name: n.to_string()
                                        .trim_end_matches(char::from(0))
                                        .to_string(),
                        create_time: 0,
                        exit_time: 0

                    });
                },
                _ => {}
            };
            self.deref_addr(ptr + flink_offset, &mut ptr);
        }
        Ok(result)
    }

    pub fn scan_pool<F>(&self, tag: &[u8; 4], mut handler: F) -> BoxResult<bool>
                        where F: FnMut(u64, &[u8], u64) -> BoxResult<bool>
                        // F(Pool Address, Pool Header Data, Pool Data Address)
                        // TODO: Pool Header as a real struct
    {
        let ntosbase = self.get_kernel_base();
        let pool_header_size = self.pdb_store.get_offset_r("_POOL_HEADER.struct_size")?;
        let minimum_block_size = self.get_minimum_block_size(tag)?;
        let code = DriverAction::ScanPoolRemote.get_code();
        let range = self.get_nonpaged_range(ntosbase)?;
        let start_address = range[0];
        let end_address = range[1];
        let mut ptr = start_address;
        while ptr < end_address {
            let mut input = InputData {
                scan_range: ScanPoolData::new(&[ptr, end_address], tag)
            };
            self.windows_ffi.device_io(code, &mut input, &mut ptr);
            // println!("found: 0x{:x}", ptr);
            if ptr >= end_address {
                break;
            }

            let pool_addr = ptr;
            let mut header = vec![0u8; pool_header_size as usize];
            self.deref_addr_ptr(pool_addr, header.as_mut_ptr(), pool_header_size);
            let chunk_size = (header[2] as u64) * 16u64;

            if pool_addr + chunk_size > end_address {
                // the chunk found is not a valid chunk for sure
                break;
            }

            // automatically reject bad chunk
            if chunk_size < minimum_block_size {
                ptr += 0x4;
                continue;
            }

            let success = handler(pool_addr, &header, pool_addr + pool_header_size)?;
            if success {
                ptr += chunk_size; /* pass this chunk */
                // ptr += 0x4;
            }
            else {
                ptr += 0x4; /* search next */
            }
        }
        Ok(true)
    }

    fn get_minimum_block_size(&self, tag: &[u8; 4]) -> BoxResult<u64> {
        // Proc -> _EPROCESS
        // Thre -> _KTHREAD
        let pool_header_size = self.pdb_store.get_offset_r("_POOL_HEADER.struct_size")?;
        if tag == b"Proc" {
            let eprocess_size = self.pdb_store.get_offset_r("_EPROCESS.struct_size")?;
            let minimum_data_size = eprocess_size + pool_header_size;
            Ok(minimum_data_size)
        }
        else if tag == b"Thre" {
            let ethread_size = self.pdb_store.get_offset_r("_EPROCESS.struct_size")?;
            let minimum_data_size = ethread_size + pool_header_size;
            Ok(minimum_data_size)
        }
        else if tag == b"File" {
            let file_object_size = self.pdb_store.get_offset_r("_FILE_OBJECT.struct_size")?;
            let minimum_data_size = file_object_size + pool_header_size;
            Ok(minimum_data_size)
        }
        else {
            Err("Tag unknown".into())
        }
    }

    pub fn deref_addr<T>(&self, addr: u64, outbuf: &mut T) {
        // println!("deref addr: 0x{:x}", addr);
        let code = DriverAction::DereferenceAddress.get_code();
        let size: usize = size_of_val(outbuf);
        let mut input = InputData {
            deref_addr: DerefAddr {
                addr,
                size: size as u64
            }
        };
        // unsafe { println!("Dereference {} bytes at 0x{:x}", input.deref_addr.size, input.deref_addr.addr) };
        self.windows_ffi.device_io(code, &mut input, outbuf);
    }

    pub fn deref_addr_ptr<T>(&self, addr: u64, outptr: *mut T, output_len: u64) {
        let code = DriverAction::DereferenceAddress.get_code();
        let mut input = InputData {
            deref_addr: DerefAddr {
                addr,
                size: output_len
            }
        };
        self.windows_ffi.device_io_raw(code,
                                       &mut input as *mut _ as *mut c_void, size_of_val(&input) as DWORD,
                                       outptr as *mut c_void, output_len as DWORD);
    }

    pub fn get_unicode_string(&self, unicode_str_addr: u64, deref: bool) -> BoxResult<String> {
        let mut strlen = 0u16;
        let mut capacity = 0u16;
        let mut bufaddr = 0u64;
        let buffer_ptr = unicode_str_addr + self.pdb_store.get_offset_r("_UNICODE_STRING.Buffer")?;
        let capacity_addr  = unicode_str_addr + self.pdb_store.get_offset_r("_UNICODE_STRING.MaximumLength")?;

        self.deref_addr(unicode_str_addr, &mut strlen);
        self.deref_addr(capacity_addr, &mut capacity);
        self.deref_addr(buffer_ptr, &mut bufaddr);

        // println!("unicode str: 0x{:x} size: 0x{:x} capacity: 0x{:x}", bufaddr, strlen, capacity);
        if bufaddr == 0 || strlen > capacity || strlen == 0 || strlen % 2 != 0 {
            return Err("Unicode string is empty".into());
        }

        if !deref {
            return Ok("".to_string());
        }

        let mut buf = vec![0u16; (strlen / 2) as usize];
        self.deref_addr_ptr(bufaddr, buf.as_mut_ptr(), strlen as u64);

        Ok(String::from_utf16(&buf)?)
    }

    pub fn get_nonpaged_range(&self, ntosbase: u64) -> BoxResult<[u64; 2]> {
        // TODO: Add support for other Windows version here
        match self.windows_ffi.short_version {
            WindowsVersion::Windows10FastRing => {
                let mistate = ntosbase + self.pdb_store.get_offset_r("MiState")?;
                let system_node_ptr = self.pdb_store.addr_decompose(
                                        mistate, "_MI_SYSTEM_INFORMATION.Hardware.SystemNodeNonPagedPool")?;
                let mut system_node_addr = 0u64;
                self.deref_addr(system_node_ptr, &mut system_node_addr);

                let mut first_va = 0u64;
                let mut last_va = 0u64;
                self.deref_addr(
                    system_node_addr
                    + self.pdb_store.get_offset_r("_MI_SYSTEM_NODE_NONPAGED_POOL.NonPagedPoolFirstVa")?,
                    &mut first_va);

                self.deref_addr(
                    system_node_addr
                    + self.pdb_store.get_offset_r("_MI_SYSTEM_NODE_NONPAGED_POOL.NonPagedPoolLastVa")?,
                    &mut last_va);

                Ok([first_va, last_va])
            },
            WindowsVersion::Windows10_2019 |
            WindowsVersion::Windows10_2018 => {
                let mistate = ntosbase + self.pdb_store.get_offset_r("MiState")?;
                let system_node_ptr = self.pdb_store.addr_decompose(
                                        mistate, "_MI_SYSTEM_INFORMATION.Hardware.SystemNodeInformation")?;
                let mut system_node_addr = 0u64;
                self.deref_addr(system_node_ptr, &mut system_node_addr);

                let mut first_va = 0u64;
                let mut last_va = 0u64;
                self.deref_addr(
                    system_node_addr
                    + self.pdb_store.get_offset_r("_MI_SYSTEM_NODE_INFORMATION.NonPagedPoolFirstVa")?,
                    &mut first_va);

                self.deref_addr(
                    system_node_addr
                    + self.pdb_store.get_offset_r("_MI_SYSTEM_NODE_INFORMATION.NonPagedPoolLastVa")?,
                    &mut last_va);

                Ok([first_va, last_va])
            },
            _ => {
                Err("Windows version for nonpaged pool algorithm is not implemented".into())
            }
        }
    }

}

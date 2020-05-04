use std::ffi::c_void;
use std::mem::{size_of_val};

use winapi::shared::ntdef::{NTSTATUS};
use winapi::shared::minwindef::{DWORD};
use winapi::um::winioctl::{
    CTL_CODE, FILE_ANY_ACCESS,
    METHOD_IN_DIRECT, METHOD_OUT_DIRECT, METHOD_BUFFERED, METHOD_NEITHER
};

use crate::pdb_store::{PdbStore};
use crate::windows::{WindowsFFI, WindowsVersion};
use crate::ioctl_protocol::{
    InputData, OffsetData, DerefAddr, ScanRange, HideProcess,
    OutputData, Nothing
};

const SIOCTL_TYPE: DWORD = 40000;

fn to_epoch(filetime: u64) -> u64 {
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
    pub pdb_store: PdbStore,
    windows_ffi: WindowsFFI,
}

impl DriverState {
    pub fn new(pdb_store: PdbStore, windows_ffi: WindowsFFI) -> Self {
        pdb_store.print_default_information();
        windows_ffi.print_version();
        Self {
            pdb_store,
            windows_ffi,
            ntosbase: 0u64,
            nonpaged_range: [0, 0],
            eprocess_traverse_result: Vec::new(),
            pool_scan_result: Vec::new()
        }
    }

    pub fn startup(&mut self) -> NTSTATUS {
        self.windows_ffi.load_driver()
        let mut input = InputData {
            offset_value: OffsetData::new(&self.pdb_store, self.windows_ffi.short_version)
        };
        self.windows_ffi.device_io(code, &mut input, &mut Nothing);
    }

    pub fn shutdown(&self) -> NTSTATUS {
        self.windows_ffi.unload_driver()
    }

    pub fn get_kernel_base(&self) -> Result<u64, io::Error> {
        let mut ntosbase = 0u64;
        self.windows_ffi.device_io(DriverAction::GetKernelBase.get_code(),
                                   &mut Nothing, &mut ntosbase);
        // println!("ntosbase: 0x{:x}", self.ntosbase);
        Ok(ntosbase)
    }

    pub fn scan_active_head(&self, ntosbase: u64) -> Result<Vec<EprocessPoolChunk>, io::Error> {
        let ps_active_head = ntosbase + self.pdb_store.get_offset("PsActiveProcessHead");
        let flink_offset = self.pdb_store.get_offset("_LIST_ENTRY.Flink");
        let eprocess_link_offset = self.pdb_store.get_offset("_EPROCESS.ActiveProcessLinks");
        let eprocess_name_offset = self.pdb_store.get_offset("_EPROCESS.ImageFileName");

        let mut ptr = ps_active_head;
        self.deref_addr(ptr + flink_offset, &mut ptr);

        let mut result: Vec<EprocessPoolChunk>;
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

    pub fn scan_pool(&self, ntosbase: u64, tag: [u8; 4],
                     handler: FnMut(&DriverState, u64) -> Result<bool, io::Error>
                    ) -> Result<bool, io::Error> {
        let range = self.get_nonpaged_range(ntosbase);
        let start_address = range[0];
        let end_address = range[1];
        let mut ptr = start_address;
        while ptr < end_address {
            let mut input = InputData {
                scan_range: ScanPoolData::new(&[ptr, end_address], tag)
            };
            self.windows_ffi.device_io(code, &mut input, &mut ptr);
            if ptr >= end_address {
                break;
            }
            handler(&self, ptr)?;
            ptr += pool_header_size;
        }
        Ok(true)
    }

    pub fn deref_addr<T>(&self, addr: u64, outbuf: &mut T) {
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

    pub fn get_unicode_string(&self, unicode_str_addr: u64) -> Result<&str, io::Error> {
        let mut strlen: u16;
        let mut bufaddr : u64;
        let buffer_ptr = unicode_str_addr + self.pdb_store.get_offset("_UNICODE_STRING.Buffer")?;

        self.defer_addr(unicode_str_addr, &mut strlen);
        self.defer_addr(buffer_ptr, &mut bufaddr);

        let mut buf = vec![0u8; strlen as usize];
        dr.deref_addr_ptr(bufaddr, buf.as_mut_ptr(), strlen);

        prinln!("unicode string {?}", buf);

        Ok(str::from_utf8(&buf)?)
    }

    pub fn get_nonpaged_range(&self, ntosbase: u64) -> Result<[u64; 2], io::Error> {
        // TODO: Add support for other Windows version here
        match self.windows_ffi.short_version {
            WindowsVersion::Windows10FastRing => {
                let mistate = ntosbase + self.pdb_store.get_offset("MiState")?;
                let system_node_ptr = self.pdb_store.addr_decompose(
                                        mistate, "_MI_SYSTEM_INFORMATION.Hardware.SystemNodeNonPagedPool")?;
                let mut system_node_addr = 0u64;
                self.deref_addr(system_node_ptr, &mut system_node_addr);

                let mut first_va = 0u64;
                let mut last_va = 0u64;
                self.deref_addr(
                    system_node_addr + self.pdb_store.get_offset(
                        "_MI_SYSTEM_NODE_NONPAGED_POOL.NonPagedPoolFirstVa")?,
                    &mut first_va);

                self.deref_addr(
                    system_node_addr + self.pdb_store.get_offset(
                        "_MI_SYSTEM_NODE_NONPAGED_POOL.NonPagedPoolLastVa")?,
                    &mut last_va);

                Ok([first_va, last_va])
            }
            _ => {
                Err("Windows version for nonpaged pool algorithm is not implemented")
            }
        }
    }

}

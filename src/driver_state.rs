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
    pub eprocess_name: String
}

impl PartialEq for EprocessPoolChunk {
    fn eq(&self, other: &Self) -> bool {
        self.eprocess_addr == other.eprocess_addr
    }
}

#[allow(dead_code)]
pub struct DriverState {
    pdb_store: PdbStore,
    windows_ffi: WindowsFFI,
    ntosbase: u64,
    nonpaged_range: [u64; 2],
    pub eprocess_traverse_result: Vec<EprocessPoolChunk>,
    pub pool_scan_result: Vec<EprocessPoolChunk>
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
    }

    pub fn shutdown(&self) -> NTSTATUS {
        self.windows_ffi.unload_driver()
    }

    // TODO: Function output and input data????
    pub fn interact(&mut self, action: DriverAction) {
        let code = action.get_code();
        println!("Driver action: {:?}", action);
        match action {
            DriverAction::SetupOffset => {
                let mut input = InputData {
                    offset_value: OffsetData::new(&self.pdb_store, self.windows_ffi.short_version)
                };
                self.windows_ffi.device_io(code, &mut input, &mut Nothing);
            },
            DriverAction::GetKernelBase => {
                self.windows_ffi.device_io(code, &mut Nothing, &mut self.ntosbase);
                println!("ntosbase: 0x{:x}", self.ntosbase);
            },
            DriverAction::ScanPsActiveHead => {
                self.interact(DriverAction::GetKernelBase);
                let ps_active_head = self.ntosbase + self.pdb_store.get_offset("PsActiveProcessHead").unwrap_or(0u64);
                let flink_offset = self.pdb_store.get_offset("_LIST_ENTRY.Flink").unwrap_or(0u64);
                let eprocess_link_offset = self.pdb_store.get_offset("_EPROCESS.ActiveProcessLinks").unwrap_or(0u64);
                let eprocess_name_offset = self.pdb_store.get_offset("_EPROCESS.ImageFileName").unwrap_or(0u64);

                let mut ptr = ps_active_head;
                self.deref_addr(ptr + flink_offset, &mut ptr);

                // println!("========================");
                // println!("Scan PsActiveProcessHead");
                while ptr != ps_active_head {
                    let mut image_name = [0u8; 15];
                    let eprocess = ptr - eprocess_link_offset;
                    self.deref_addr(eprocess + eprocess_name_offset, &mut image_name);
                    match std::str::from_utf8(&image_name) {
                        Ok(n) => {
                            // TODO: save to somewhere
                            // println!("_EPROCESS at 0x{:x} of {}", eprocess, n);
                            self.eprocess_traverse_result.push(EprocessPoolChunk {
                                pool_addr: 0,
                                eprocess_addr: eprocess,
                                eprocess_name: n.to_string().trim_end_matches(char::from(0))
                                                .to_string()

                            });
                        },
                        _ => {}
                    };
                    self.deref_addr(ptr + flink_offset, &mut ptr);
                }
                // println!("========================");

                // test call to check result
                self.windows_ffi.device_io(code, &mut Nothing, &mut Nothing);
            },
            DriverAction::ScanPool => {
                self.get_nonpaged_range();
                let mut input = InputData {
                    scan_range: ScanRange::new(&self.nonpaged_range)
                };
                self.windows_ffi.device_io(code, &mut input, &mut Nothing);
            },
            DriverAction::ScanPoolRemote => {
                self.get_nonpaged_range();
                let start_address = self.nonpaged_range[0];
                let end_address = self.nonpaged_range[1];

                let pool_header_size = self.pdb_store.get_offset("_POOL_HEADER.struct_size").unwrap_or(0u64);
                let eprocess_name_offset = self.pdb_store.get_offset("_EPROCESS.ImageFileName").unwrap_or(0u64);
                let eprocess_create_time_offset = self.pdb_store.get_offset("_EPROCESS.CreateTime").unwrap_or(0u64);
                let eprocess_size = self.pdb_store.get_offset("_EPROCESS.struct_size").unwrap_or(0u64);

                let mut ptr = start_address;
                while ptr < end_address {
                    let mut input = InputData {
                        scan_range: ScanRange::new(&[ptr, end_address])
                    };
                    self.windows_ffi.device_io(code, &mut input, &mut ptr);
                    if ptr >= end_address {
                        break;
                    }
                    let pool_addr = ptr;
                    ptr += pool_header_size;

                    let mut pool = vec![0u8; pool_header_size as usize];
                    self.deref_addr_ptr(pool_addr, pool.as_mut_ptr(), pool_header_size);
                    // TODO: Use pdb to parse, bit mangling and stuff
                    // println!("=========================");
                    // println!("Pool at 0x{:x}", pool_addr);
                    // println!("Previos Size: 0x{:x}", pool[0]);
                    // println!("Pool index  : {:x}", pool[1]);
                    // println!("Block size  : 0x{:x}", (pool[2] as u64) * 16u64); // CHUNK_SIZE = 16
                    // println!("Pool type   : {}", pool[3]);
                    // println!("Pool tag    : {}", std::str::from_utf8(&pool[4..8]).unwrap());

                    let pool_size = (pool[2] as u64) * 16u64;
                    let eprocess_valid_start = pool_addr + pool_header_size;
                    let eprocess_valid_end = pool_addr + pool_size - eprocess_size;
                    let mut found_valid = false;
                    let mut try_eprocess_ptr = eprocess_valid_start;

                    while !found_valid || try_eprocess_ptr < eprocess_valid_end {
                        let mut create_time = 0u64;
                        self.deref_addr(try_eprocess_ptr + eprocess_create_time_offset, &mut create_time);
                        if self.windows_ffi.valid_process_time(create_time) {
                            found_valid = true;
                            let mut image_name = [0u8; 15];
                            self.deref_addr(try_eprocess_ptr + eprocess_name_offset, &mut image_name);
                            // println!("_EPROCESS at 0x{:x} of {}",
                            //          try_eprocess_ptr, std::str::from_utf8(&image_name).unwrap());
                            // TODO: save result
                            self.pool_scan_result.push(EprocessPoolChunk {
                                pool_addr,
                                eprocess_addr: try_eprocess_ptr,
                                eprocess_name: std::str::from_utf8(&image_name).unwrap()
                                                    .to_string().trim_end_matches(char::from(0))
                                                    .to_string()
                            });
                            break;
                        }
                        try_eprocess_ptr += 0x4;        // search exhaustively
                    }
                    if !found_valid {
                        println!("Not an eprocess maybe");
                    }
                }
            },
            DriverAction::HideProcess => {
                let s = String::from("notepad.exe");
                let s_bytes = s.as_bytes();
                let mut name = [0u8; 15];
                for i in 0..s.len() {
                    name[i] = s_bytes[i];
                };
                let mut input = InputData {
                    hide_process: HideProcess {
                        name,
                        size: s.len() as u64
                    }
                };
                self.windows_ffi.device_io(code, &mut input, &mut Nothing);
            }
            _ => {}
        };
    }

    fn deref_addr<T>(&self, addr: u64, outbuf: &mut T) {
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

    fn deref_addr_ptr<T>(&self, addr: u64, outptr: *mut T, output_len: u64) {
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

    #[allow(dead_code)]
    fn get_nonpaged_range(&mut self) {
        // TODO: Add support for other Windows version here
        match self.windows_ffi.short_version {
            WindowsVersion::Windows10FastRing => {
                let mistate = self.ntosbase + self.pdb_store.get_offset("MiState").unwrap_or(0u64);
                let system_node_ptr = self.pdb_store.addr_decompose(
                                        mistate, "_MI_SYSTEM_INFORMATION.Hardware.SystemNodeNonPagedPool")
                                        .unwrap_or(0u64);
                let mut system_node_addr = 0u64;
                self.deref_addr(system_node_ptr, &mut system_node_addr);

                let mut first_va = 0u64;
                let mut last_va = 0u64;
                self.deref_addr(
                    system_node_addr + self.pdb_store.get_offset(
                        "_MI_SYSTEM_NODE_NONPAGED_POOL.NonPagedPoolFirstVa").unwrap_or(0u64),
                    &mut first_va);

                self.deref_addr(
                    system_node_addr + self.pdb_store.get_offset(
                        "_MI_SYSTEM_NODE_NONPAGED_POOL.NonPagedPoolLastVa").unwrap_or(0u64),
                    &mut last_va);

                self.nonpaged_range[0] = first_va;
                self.nonpaged_range[1] = last_va;
            }
            _ => {}
        };
        println!("Nonpaged pool range: 0x{:x} - 0x{:x}", self.nonpaged_range[0], self.nonpaged_range[1]);
    }
}

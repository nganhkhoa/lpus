use crate::pdb_store::PdbStore;
use crate::windows::WindowsVersion;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetData {
    eprocess_name_offset: u64,
    eprocess_link_offset: u64,
    list_blink_offset: u64,
    process_head_offset: u64,
    mistate_offset: u64,
    hardware_offset: u64,
    system_node_offset: u64,
    first_va_offset: u64,
    last_va_offset: u64,
    large_page_table_offset: u64,
    large_page_size_offset: u64,
    pool_chunk_size: u64,
}

// TODO: Move to WindowsScanStrategy and return the corresponding struct base on Windows version
impl OffsetData {
    pub fn new(pdb_store: &PdbStore, windows_version: WindowsVersion) -> Self {
        match windows_version {
            WindowsVersion::Windows10FastRing => Self {
                eprocess_name_offset: pdb_store.get_offset("_EPROCESS.ImageFileName").unwrap_or(0u64),
                eprocess_link_offset: pdb_store.get_offset("_EPROCESS.ActiveProcessLinks").unwrap_or(0u64),
                list_blink_offset: pdb_store.get_offset("_LIST_ENTRY.Blink").unwrap_or(0u64),
                process_head_offset: pdb_store.get_offset("PsActiveProcessHead").unwrap_or(0u64),
                mistate_offset: pdb_store.get_offset("MiState").unwrap_or(0u64),
                hardware_offset: pdb_store.get_offset("_MI_SYSTEM_INFORMATION.Hardware").unwrap_or(0u64),
                system_node_offset: pdb_store.get_offset("_MI_HARDWARE_STATE.SystemNodeNonPagedPool").unwrap_or(0u64),
                first_va_offset: pdb_store.get_offset("_MI_SYSTEM_NODE_NONPAGED_POOL.NonPagedPoolFirstVa").unwrap_or(0u64),
                last_va_offset: pdb_store.get_offset("_MI_SYSTEM_NODE_NONPAGED_POOL.NonPagedPoolLastVa").unwrap_or(0u64),
                large_page_table_offset: pdb_store.get_offset("PoolBigPageTable").unwrap_or(0u64),
                large_page_size_offset: pdb_store.get_offset("PoolBigPageTableSize").unwrap_or(0u64),
                pool_chunk_size: pdb_store.get_offset("_POOL_HEADER.struct_size").unwrap_or(0u64),
            },
            // TODO: Add other version of Windows here
            _ => Self {
                eprocess_name_offset: 0u64,
                eprocess_link_offset: 0u64,
                list_blink_offset: 0u64,
                process_head_offset: 0u64,
                mistate_offset: 0u64,
                hardware_offset: 0u64,
                system_node_offset: 0u64,
                first_va_offset: 0u64,
                last_va_offset: 0u64,
                large_page_table_offset: 0u64,
                large_page_size_offset: 0u64,
                pool_chunk_size: 0u64,
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct DerefAddr {
    pub addr: u64,
    pub size: u64
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ScanPoolData {
    pub start: u64,
    pub end: u64,
    pub tag: u32
}

impl ScanPoolData{
    pub fn new(arr: &[u64; 2], tag: &[u8; 4]) -> Self {
        Self {
            start: arr[0],
            end: arr[1],
            tag: u32::from_le_bytes(*tag)
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HideProcess {
    pub name: [u8; 15],
    pub size: u64
}

#[repr(C)]
pub union InputData {
    pub offset_value: OffsetData,
    pub deref_addr: DerefAddr,
    pub scan_range: ScanPoolData,
    pub hide_process: HideProcess,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Nothing; // for empty data

#[repr(C)]
pub union OutputData {
    pub nothing: Nothing,
}

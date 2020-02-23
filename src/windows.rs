use std::ffi::CString;
use widestring::{U16CString};

use winapi::shared::ntdef::*;
use winapi::shared::minwindef::{DWORD, HKEY, HMODULE};
use winapi::um::winnt::{
    SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, TOKEN_ADJUST_PRIVILEGES, LUID_AND_ATTRIBUTES,
    REG_DWORD, REG_SZ, REG_OPTION_NON_VOLATILE, KEY_WRITE,
    PRTL_OSVERSIONINFOW, OSVERSIONINFOW
};

use winapi::um::handleapi::*;
use winapi::um::libloaderapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::winbase::*;
use winapi::um::winreg::*;

#[allow(dead_code)]
#[derive(Debug)]
pub enum WindowsVersion {
    Windows10_2015,
    Windows10_2016,
    Windows10_2017,
    Windows10_2018,
    Windows10_2019,
    Windows10_2020,
    Windows10FastRing,
    Windows10VersionUnknown
}

#[allow(dead_code)]
pub struct WindowsFFI {
    pub version_info: OSVERSIONINFOW,
    pub short_version: WindowsVersion,
    driver_registry_string: UNICODE_STRING,
    ntdll: HMODULE,
    nt_load_driver: extern "stdcall" fn(PUNICODE_STRING) -> NTSTATUS,
    nt_unload_driver: extern "stdcall" fn(PUNICODE_STRING) -> NTSTATUS,
    rtl_init_unicode_str: extern "stdcall" fn(PUNICODE_STRING, PCWSTR),
    rtl_get_version: extern "system" fn(PRTL_OSVERSIONINFOW) -> NTSTATUS,
}

impl WindowsFFI {
    pub fn new() -> Self {
        let str_ntdll = CString::new("ntdll").expect("");
        let str_nt_load_driver = CString::new("NtLoadDriver").expect("");
        let str_nt_unload_driver = CString::new("NtUnloadDriver").expect("");
        let str_rtl_init_unicode_str = CString::new("RtlInitUnicodeString").expect("");
        let str_rtl_get_version = CString::new("RtlGetVersion").expect("");
        let str_se_load_driver_privilege = CString::new("SeLoadDriverPrivilege").expect("");

        let str_driver_path = CString::new("\\SystemRoot\\System32\\DRIVERS\\nganhkhoa.sys").expect("");
        let str_registry_path = CString::new("System\\CurrentControlSet\\Services\\nganhkhoa").expect("");
        let str_driver_reg =
            U16CString::from_str("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\nganhkhoa").expect("");
        let str_type = CString::new("Type").expect("");
        let str_error_control = CString::new("ErrorControl").expect("");
        let str_start = CString::new("Start").expect("");
        let str_image_path = CString::new("ImagePath").expect("");

        let mut str_driver_reg_unicode = UNICODE_STRING::default();
        let mut version_info = OSVERSIONINFOW {
            dwOSVersionInfoSize: 0u32,
            dwMajorVersion: 0u32,
            dwMinorVersion: 0u32,
            dwBuildNumber: 0u32,
            dwPlatformId: 0u32,
            szCSDVersion: [0u16; 128],
        };

        let ntdll: HMODULE;
        let nt_load_driver: extern "stdcall" fn(PUNICODE_STRING) -> NTSTATUS;
        let nt_unload_driver: extern "stdcall" fn(PUNICODE_STRING) -> NTSTATUS;
        let rtl_init_unicode_str: extern "stdcall" fn(PUNICODE_STRING, PCWSTR);
        let rtl_get_version: extern "system" fn(PRTL_OSVERSIONINFOW) -> NTSTATUS;

        // some pointer unsafe C code
        unsafe {
            ntdll = LoadLibraryA(str_ntdll.as_ptr());
            let nt_load_driver_ = GetProcAddress(ntdll, str_nt_load_driver.as_ptr());
            let nt_unload_driver_ = GetProcAddress(ntdll, str_nt_unload_driver.as_ptr());
            let rtl_init_unicode_str_ = GetProcAddress(ntdll, str_rtl_init_unicode_str.as_ptr());
            let rtl_get_version_ = GetProcAddress(ntdll, str_rtl_get_version.as_ptr());

            nt_load_driver = std::mem::transmute(nt_load_driver_);
            nt_unload_driver = std::mem::transmute(nt_unload_driver_);
            rtl_init_unicode_str = std::mem::transmute(rtl_init_unicode_str_);
            rtl_get_version = std::mem::transmute(rtl_get_version_);

            // setup registry
            let mut registry_key: HKEY = std::ptr::null_mut();
            RegCreateKeyExA(
                HKEY_LOCAL_MACHINE, str_registry_path.as_ptr(),
                0, std::ptr::null_mut(),
                REG_OPTION_NON_VOLATILE, KEY_WRITE,
                std::ptr::null_mut(), &mut registry_key, std::ptr::null_mut()
            );
            let type_value: [u8; 4] = 1u32.to_le_bytes();
            let error_control_value: [u8; 4] = 1u32.to_le_bytes();
            let start_value: [u8; 4] = 3u32.to_le_bytes();
            let registry_values = [
                (str_type.as_ptr(), REG_DWORD, type_value.as_ptr(), 4),
                (str_error_control.as_ptr(), REG_DWORD, error_control_value.as_ptr(), 4),
                (str_start.as_ptr(), REG_DWORD, start_value.as_ptr(), 4),
                (str_image_path.as_ptr(), REG_SZ,
                    str_driver_path.as_ptr() as *const u8, str_driver_path.to_bytes().len() + 1)
            ];
            for &(key, keytype, value_ptr, size_in_bytes) in &registry_values {
                RegSetValueExA(
                    registry_key, key, 0,
                    keytype, value_ptr, size_in_bytes as u32
                );
            }
            RegCloseKey(registry_key);

            // Setup privilege SeLoadDriverPrivilege
            let mut token_handle: HANDLE = std::ptr::null_mut();
            let mut luid = LUID::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle);
            LookupPrivilegeValueA(std::ptr::null_mut(), str_se_load_driver_privilege.as_ptr(), &mut luid);
            let mut new_token_state = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED
                }]
            };
            AdjustTokenPrivileges(
                token_handle, 0, &mut new_token_state, 16, std::ptr::null_mut(), std::ptr::null_mut());
            CloseHandle(token_handle);

            // init string for load and unload driver routine
            rtl_init_unicode_str(&mut str_driver_reg_unicode, str_driver_reg.as_ptr() as *const u16);
        }

        rtl_get_version(&mut version_info);

        let short_version = match version_info.dwBuildNumber {
            17134 | 17763 => WindowsVersion::Windows10_2018,
            18362 | 18363 => WindowsVersion::Windows10_2019,
            19041 => WindowsVersion::Windows10_2020,
            _ if version_info.dwBuildNumber >= 19536 => WindowsVersion::Windows10FastRing,
            _ => WindowsVersion::Windows10VersionUnknown
        };

        Self {
            version_info,
            short_version,
            driver_registry_string: str_driver_reg_unicode,
            ntdll,
            nt_load_driver,
            nt_unload_driver,
            rtl_init_unicode_str,
            rtl_get_version
        }
    }

    pub fn load_driver(&mut self) -> NTSTATUS {
        (self.nt_load_driver)(&mut self.driver_registry_string)
    }

    pub fn unload_driver(&mut self) -> NTSTATUS {
        (self.nt_unload_driver)(&mut self.driver_registry_string)
    }

    #[allow(dead_code)]
    pub fn get_build_number(&self) -> DWORD {
        self.version_info.dwBuildNumber
    }

    #[allow(dead_code)]
    pub fn print_version(&self) {
        println!("Windows version: {}.{}.{} {:?}",
            self.version_info.dwMajorVersion,
            self.version_info.dwMinorVersion,
            self.version_info.dwBuildNumber,
            self.short_version
        );
    }
}

use std::error::Error;
use std::io;
use std::io::{Read};
use std::path::{PathBuf};
use std::fs::File;
use std::collections::HashMap;

use pdb::{
    PDB, SymbolData, TypeData, ClassType, ModifierType, Rva,
    FallibleIterator, TypeFinder, TypeIndex
};
use app_dirs::{AppInfo, AppDataType, app_dir};

use crate::address::Address;

const APP_INFO: AppInfo = AppInfo { name: "lpus", author: "nganhkhoa" };

const KERNEL_PDB_NAME: &str = "ntkrnlmp.pdb";
const NTOSKRNL_PATH: &str = "C:\\Windows\\System32\\ntoskrnl.exe";
const PDB_SERVER_PATH: &str = "http://msdl.microsoft.com/download/symbols";

type BoxResult<T> = Result<T, Box<dyn Error>>;

type SymbolStore = HashMap<String, u64>;
type StructStore = HashMap<String, HashMap<String, (String, u64)>>;

pub struct PdbStore {
    pub symbols: SymbolStore,
    pub structs: StructStore
}

impl PdbStore {
    pub fn get_offset_r(&self, name: &str) -> BoxResult<u64> {
        self.get_offset(name)
            .ok_or(format!("{} is not found in PDB", name).into())
    }
    #[allow(dead_code)]
    pub fn get_offset(&self, name: &str) -> Option<u64> {
        if name.contains(".") {
            let v: Vec<&str> = name.split_terminator('.').collect();
            match self.structs.get(v[0]) {
                Some(member_info) => {
                    match member_info.get(v[1]) {
                        Some((_memtype, offset)) => Some(*offset),
                        None => None
                    }
                },
                None => None
            }
        }
        else {
            match self.symbols.get(name) {
                Some(offset) => Some(*offset),
                None => None
            }
        }
    }

    #[allow(dead_code)]
    pub fn addr_decompose(&self, addr: u64, full_name: &str) -> BoxResult<u64>{
        if !full_name.contains(".") {
            return Err("Not decomposable".into());
        }

        let mut name_part: Vec<&str> = full_name.split_terminator('.').collect();
        let mut next: Vec<_> = name_part.drain(2..).collect();
        match self.structs.get(name_part[0]) {
            Some(member_info) => {
                match member_info.get(name_part[1]) {
                    Some((memtype, offset)) => {
                        if next.len() != 0 {
                            if memtype.contains("*") {
                                return Err(format!("Cannot dereference pointer at {} {}", memtype, name_part[1]).into());
                            }
                            next.insert(0, memtype);
                            self.addr_decompose(addr + *offset, &next.join("."))
                        }
                        else {
                            Ok(addr + *offset)
                        }
                    },
                    None => Err(format!("Not found member {}", name_part[1]).into())
                }
            },
            None => Err(format!("Struct {} not found", name_part[0]).into())
        }
    }

    pub fn decompose(&self, source: &Address, full_name: &str) -> BoxResult<Address> {
        // println!("decompose {}", full_name);
        if !full_name.contains(".") {
            return Err("Not decomposable".into());
        }

        let mut name_part: Vec<&str> = full_name.split_terminator('.').collect();
        let mut next: Vec<_> = name_part.drain(2..).collect();
        let member_info = self.structs.get(name_part[0])
                          .ok_or(format!("No struct {}", name_part[0]))?;
        let (memtype, offset) = member_info.get(name_part[1])
                                .ok_or(format!("No member {} in {}", name_part[1], name_part[0]))?;

        if next.len() == 0 {
            return Ok(source.clone() + *offset);
        }
        if memtype.contains("*") {
            let mut t = memtype.clone(); // remove *
            t.pop();
            next.insert(0, &t);
            let p = Address::from_ptr(source.clone() + *offset);
            self.decompose(&p, &next.join("."))

        }
        else {
            next.insert(0, memtype);
            self.decompose(&(source.clone() + *offset), &next.join("."))
        }
    }

    #[allow(dead_code)]
    pub fn print_default_information(&self) {
        let need_symbols = [
            "PsLoadedModuleList", "PsActiveProcessHead", "KeNumberNodes",
            "PoolBigPageTable", "PoolBigPageTableSize",
            // "PoolVector", "ExpNumberOfNonPagedPools",
            "KdDebuggerDataBlock", "MmNonPagedPoolStart", "MmNonPagedPoolEnd",              // Windows XP
            "MiNonPagedPoolStartAligned", "MiNonPagedPoolEnd", "MiNonPagedPoolBitMap",      // Windows 7, 8
            "MiNonPagedPoolBitMap", "MiNonPagedPoolVaBitMap",
            "MiState"                                                                       // Windows 10
        ];

        let mut need_structs = HashMap::new();
        need_structs.insert("_POOL_HEADER", vec![
            "struct_size",
            "PoolType", "BlockSize", "PoolTag"
        ]);
        need_structs.insert("_PEB", vec![]);
        need_structs.insert("_LIST_ENTRY", vec![
            "Flink", "Blink"
        ]);
        need_structs.insert("_FILE_OBJECT", vec![
            "FileName"
        ]);
        need_structs.insert("_EPROCESS", vec![
            "struct_size",
            "UniqueProcessId", "ActiveProcessLinks", "CreateTime",
            "Peb", "ImageFilePointer", "ImageFileName", "ThreadListHead"
        ]);
        need_structs.insert("_KDDEBUGGER_DATA64", vec![
            "MmNonPagedPoolStart", "MmNonPagedPoolEnd",                                     // Windows XP
        ]);
        need_structs.insert("_POOL_TRACKER_BIG_PAGES", vec![]);

        // these struct supports finding NonPagedPool{First,Last}Va in windows 10
        need_structs.insert("_MI_SYSTEM_INFORMATION", vec![
            "Hardware",                                                 // windows 10 2016+
            "SystemNodeInformation"                                     // windows 10 2015
        ]);
        need_structs.insert("_MI_HARDWARE_STATE", vec![
            "SystemNodeInformation",                                    // till windows 10 1900
            "SystemNodeNonPagedPool"                                    // windows insider, 2020
        ]);
        need_structs.insert("_MI_SYSTEM_NODE_INFORMATION", vec![        // till windows 10 1900
            "NonPagedPoolFirstVa", "NonPagedPoolLastVa",
            "NonPagedBitMap",                                           // missing on windows 10 1900+
            "DynamicBitMapNonPagedPool"                                 // some weird field
        ]);
        need_structs.insert("_MI_SYSTEM_NODE_NONPAGED_POOL", vec![      // windows insider, 2020
            "NonPagedPoolFirstVa", "NonPagedPoolLastVa",
            "DynamicBitMapNonPagedPool"                                 // some weird field
        ]);
        need_structs.insert("_MI_DYNAMIC_BITMAP", vec![]);
        need_structs.insert("_RTL_BITMAP", vec![]);                     // windows 10 until 2020
        need_structs.insert("_RTL_BITMAP_EX", vec![]);                  // windows insider, 2020

        for &symbol in &need_symbols {
            match self.symbols.get(symbol) {
                Some(offset) => println!("0x{:x} {}", offset, symbol),
                None => {}
            }
        }

        for (&struct_name, members) in &need_structs {
            match self.structs.get(struct_name) {
                Some(member_info) => {
                    for &member in members {
                        match member_info.get(member) {
                            Some((memtype, offset)) =>
                                println!("0x{:x} {} {}.{}", offset, memtype, struct_name, member),
                            None => {}
                        }
                    }
                },
                None => {}
            }
        }
    }

    pub fn dt(&self, struct_name: &str) -> BoxResult<()> {
        let member_info = self.structs.get(struct_name).ok_or(format!("no struct named {}", struct_name))?;
        let (_, struct_size) = member_info.get("struct_size").ok_or("")?;
        println!("// 0x{:x} bytes", struct_size);
        println!("struct {} {{", struct_name);

        // Vec<(offset, type, name)>
        let mut members: Vec<(u64, String, String)> = Vec::new();
        for (name, (t, offset)) in member_info.iter() {
            if name != "struct_size" {
                members.push((*offset, t.to_string(), name.to_string()));
            }
        }
        members.sort_by(|(o1,_,_), (o2,_,_)| o1.partial_cmp(o2).unwrap());

        for (offset, memtype, member) in members.iter() {
            println!("  +0x{:x} {} {};", offset, memtype, member);
        }

        println!("}} // {}", struct_name);
        Ok(())
    }
}

fn get_type_as_str(type_finder: &TypeFinder, typ: &TypeIndex) -> String {
    match type_finder.find(*typ).unwrap().parse().unwrap() {
        TypeData::Class(ct) => {
            format!("{}", ct.name.to_string())
        },
        TypeData::Primitive(pt) => {
            format!("{:?}", pt.kind)
        },
        TypeData::Pointer(pt) => {
            format!("{}*", get_type_as_str(type_finder, &pt.underlying_type))
        },
        TypeData::StaticMember(st) => {
            format!("static {}", get_type_as_str(type_finder, &st.field_type))
        },
        TypeData::Array(at) => {
            format!("{}{:?}",
                get_type_as_str(type_finder, &at.element_type), /* get_type_as_str(type_finder, &at.indexing_type), */ at.dimensions)
        },
        // TypeData::Enumeration(et) => {
        //     format!("enumeration")
        // },
        // TypeData::Enumerate(et) => {
        //     format!("enumerate")
        // },
        // TypeData::MemberFunction(mft) => {
        //     format!("member function")
        // },
        // TypeData::OverloadedMethod(ovmt) => {
        //     format!("overloaded method")
        // },
        // TypeData::Nested(nt) => {
        //     format!("nested")
        // },
        // TypeData::BaseClass(bct) => {
        //     format!("base class")
        // },
        // TypeData::VirtualBaseClass(vbct) => {
        //     format!("virtual base class")
        // },
        // TypeData::VirtualFunctionTablePointer(vftpt) => {
        //     format!("virtual function table pointer")
        // },
        TypeData::Procedure(pt) => {
            let rettype = match pt.return_type {
                Some(rt) => get_type_as_str(type_finder, &rt),
                _ => "UNKNOWN".to_string()
            };
            format!("{}({})", rettype, get_type_as_str(type_finder, &pt.argument_list))
        },
        TypeData::Modifier(mt) => {
            match mt {
                ModifierType { constant: true, volatile: true, unaligned: true, .. } =>
                    format!("const volatile unaligned {}", get_type_as_str(type_finder, &mt.underlying_type)),
                ModifierType { constant: true, volatile: true, unaligned: false, .. } =>
                    format!("const volatile {}", get_type_as_str(type_finder, &mt.underlying_type)),
                ModifierType { constant: true, volatile: false, unaligned: true, .. } =>
                    format!("const unaligned {}", get_type_as_str(type_finder, &mt.underlying_type)),
                ModifierType { constant: false, volatile: true, unaligned: true, .. } =>
                    format!("volatile unaligned {}", get_type_as_str(type_finder, &mt.underlying_type)),
                ModifierType { constant: true, volatile: false, unaligned: false, .. } =>
                    format!("const {}", get_type_as_str(type_finder, &mt.underlying_type)),
                ModifierType { constant: false, volatile: true, unaligned: false, .. } =>
                    format!("volatile {}", get_type_as_str(type_finder, &mt.underlying_type)),
                ModifierType { constant: false, volatile: false, unaligned: true, .. } =>
                    format!("unaligned {}", get_type_as_str(type_finder, &mt.underlying_type)),
                _ => format!("modifier {}", get_type_as_str(type_finder, &mt.underlying_type))
            }
        },
        // TypeData::Union(ut) => {
        //     format!("union")
        // },
        // TypeData::Bitfield(bft) => {
        //     format!("bitfield")
        // },
        TypeData::FieldList(_flt) => {
            format!("fieldlist")
        },
        // TypeData::ArgumentList(alt) => {
        //     format!("arglist")
        // },
        // TypeData::MethodList(mlt) => {
        //     format!("methodlist")
        // },
        unk => {
            match unk.name() {
                Some(s) => format!("{}", s.to_string()),
                _ => "UNNOWN".to_string()
            }
        }
    }
}

fn get_guid_age(exe_file: &str) -> BoxResult<(String, u32)>{
    // TODO: Check file existance
    let mut file = File::open(exe_file)?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut buffiter = buffer.chunks(4);
    while buffiter.next().unwrap() != [0x52, 0x53, 0x44, 0x53] {
        // signature == RSDS
    }

    // next 16 bytes is guid in raw bytes
    let raw_guid: Vec<u8> = vec![
        buffiter.next().unwrap(),
        buffiter.next().unwrap(),
        buffiter.next().unwrap(),
        buffiter.next().unwrap(),
    ].concat();

    // guid to hex string
    let guid = (vec![
        raw_guid[3], raw_guid[2], raw_guid[1], raw_guid[0],
        raw_guid[5], raw_guid[4],
        raw_guid[7], raw_guid[6],
        raw_guid[8], raw_guid[9], raw_guid[10], raw_guid[11],
        raw_guid[12], raw_guid[13], raw_guid[14], raw_guid[15],
    ].iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>()).join("");

    // next 4 bytes is age, in little endian
    let raw_age = buffiter.next().unwrap();
    let age = u32::from_le_bytes([
        raw_age[0], raw_age[1], raw_age[2], raw_age[3]
    ]);

    Ok((guid, age))
}

fn pdb_exists(pdbname: &str, guid: &str, age: u32) -> BoxResult<(bool, PathBuf)> {
    // Use a folder at %APPDATA% to save pdb files
    // %APPDATA%\nganhkhoaa\lpus
    // |--ntkrnlmp.pdb
    // |--|--GUID
    // |--|--|--ntkrnlmp.pdb
    // |--file.pdb
    // |--|--GUID
    // |--|--|--file.pdb
    let mut pdb_location = app_dir(AppDataType::UserData, &APP_INFO,
                                   &format!("{}/{}/{}", pdbname, guid, age))?;
    pdb_location.push(pdbname);
    Ok((pdb_location.exists(), pdb_location))
}

fn download_pdb(pdbname: &str, guid: &str, age: u32, outfile: &PathBuf) -> BoxResult<()> {
    let downloadurl = format!("{}/{}/{}{:X}/{}", PDB_SERVER_PATH, pdbname, guid, age, pdbname);
    println!("{}", downloadurl);

    let mut resp = reqwest::blocking::get(&downloadurl)?;
    let mut out = File::create(outfile)?;
    io::copy(&mut resp, &mut out)?;
    Ok(())
}

pub fn parse_pdb() -> BoxResult<PdbStore> {
    // TODO: Resolve pdb name
    // ntoskrnl.exe -> ntkrnlmp.pdb
    // tcpip.sys -> tcpip.pdb ?????
    // There may be more pdb files in the future
    let (guid, age) = get_guid_age(NTOSKRNL_PATH)?;
    let (exists, pdb_path) = pdb_exists(KERNEL_PDB_NAME, &guid, age)?;
    if !exists {
        println!("PDB not found, download into {:?}", pdb_path);
        download_pdb(KERNEL_PDB_NAME, &guid, age, &pdb_path)?;
    }
    let f = File::open(pdb_path)?;
    let mut pdb = PDB::open(f)?;

    let info = pdb.pdb_information()?;
    let dbi = pdb.debug_information()?;
    println!("PDB for {}, guid: {}, age: {}\n",
        dbi.machine_type().unwrap(), info.guid, dbi.age().unwrap_or(0));

    let type_information = pdb.type_information()?;
    let mut type_finder = type_information.type_finder();
    let mut iter = type_information.iter();
    while let Some(_typ) = iter.next().unwrap() {
        type_finder.update(&iter);
    }

    let mut symbol_extracted: SymbolStore = HashMap::new();
    let addr_map = pdb.address_map()?;
    let glosym = pdb.global_symbols()?;
    let mut symbols = glosym.iter();
    while let Some(symbol) = symbols.next().unwrap() {
        match symbol.parse() {
            Ok(SymbolData::PublicSymbol(data)) => {
                let name = symbol.name().unwrap().to_string();
                let Rva(rva) = data.offset.to_rva(&addr_map).unwrap_or_default();
                symbol_extracted.insert(format!("{}", name), rva as u64);
            },
            _ => {
            }
        }
    }

    let mut struct_extracted: StructStore = HashMap::new();
    iter = type_information.iter();
    while let Some(typ) = iter.next().unwrap() {
        match typ.parse() {
            Ok(TypeData::Class(ClassType {name, fields: Some(fields), size, ..})) => {
                let mut struct_fields = HashMap::new();
                struct_fields.insert("struct_size".to_string(), ("u32".to_string(), size as u64));
                match type_finder.find(fields).unwrap().parse().unwrap() {
                    TypeData::FieldList(list) => {
                        for field in list.fields {
                            if let TypeData::Member(member) = field {
                                let mem_typ = get_type_as_str(&type_finder, &member.field_type);
                                struct_fields.insert(
                                    format!("{}", member.name), (mem_typ, member.offset as u64));
                            }
                        }
                    }
                    _ => {}
                }
                struct_extracted.insert(format!("{}", name), struct_fields);
            },
            _ => {}
        }
    }

    Ok(PdbStore {
        symbols: symbol_extracted,
        structs: struct_extracted
    })
}

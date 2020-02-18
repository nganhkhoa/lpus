extern crate reqwest;

use std::io;
use std::io::Read;
use std::fs::File;
use std::path::Path;
use std::collections::HashMap;

use pdb::PDB;
use pdb::SymbolData;
use pdb::TypeData;
use pdb::ClassType;
use pdb::ModifierType;

use pdb::FallibleIterator;
use pdb::TypeFinder;
use pdb::TypeIndex;

const PDBNAME: &str = "ntkrnlmp.pdb";
const NTOSKRNL_PATH: &str = "C:\\Windows\\System32\\ntoskrnl.exe";
const PDB_SERVER_PATH: &str = "http://msdl.microsoft.com/download/symbols";

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

fn parse_pdb() {
    let f = File::open("ntkrnlmp.pdb").expect("No such file ./ntkrnlmp.pdb");
    let mut pdb = PDB::open(f).expect("Cannot open as a PDB file");

    let info = pdb.pdb_information().expect("Cannot get pdb information");
    let dbi = pdb.debug_information().expect("cannot get debug information");
    println!("PDB for {}, guid: {}, age: {},", dbi.machine_type().unwrap(), info.guid, dbi.age().unwrap_or(0));
    println!("");

    let type_information = pdb.type_information().expect("Cannot get type information");
    let mut type_finder = type_information.type_finder();
    let mut iter = type_information.iter();
    while let Some(_typ) = iter.next().unwrap() {
        type_finder.update(&iter);
    }

    // find global symbols offset
    let addr_map = pdb.address_map().expect("Cannot get address map");
    let glosym = pdb.global_symbols().expect("Cannot get global symbols");
    let mut symbols = glosym.iter();
    let need_symbols = [
        "PsLoadedModuleList", "PsActiveProcessHead", "KeNumberNodes",
        // "PoolVector", "ExpNumberOfNonPagedPools",
        "KdDebuggerDataBlock", "MmNonPagedPoolStart", "MmNonPagedPoolEnd",              // Windows XP
        "MiNonPagedPoolStartAligned", "MiNonPagedPoolEnd", "MiNonPagedPoolBitMap",      // Windows 7, 8
        "MiNonPagedPoolBitMap", "MiNonPagedPoolVaBitMap",
        "MiState"                                                                       // Windows 10
    ];
    while let Some(symbol) = symbols.next().unwrap() {
        match symbol.parse() {
            Ok(SymbolData::PublicSymbol(data)) => {
                let name = symbol.name().unwrap().to_string();
                for sym in need_symbols.iter() {
                    if &name == sym {
                        let rva = data.offset.to_rva(&addr_map).unwrap_or_default();
                        println!("{} {} {} {}:{}",
                            get_type_as_str(&type_finder, &(symbol.raw_kind() as u32)), name, rva, data.offset.section, data.offset.offset);
                    }
                }
            },
            _ => {
                // println!("Something else");
            }
        }
    }
    println!("");

    let mut need_structs = HashMap::new();
    // need_structs.insert("_KLDR_DATA_TABLE_ENTRY", vec![]);
    need_structs.insert("_PEB", vec![]);
    need_structs.insert("_LIST_ENTRY", vec![]);
    need_structs.insert("_EPROCESS", vec![]);
    need_structs.insert("_KDDEBUGGER_DATA64", vec![
        "MmNonPagedPoolStart", "MmNonPagedPoolEnd",                                     // Windows XP
        "MiNonPagedPoolStartAligned", "MiNonPagedPoolEnd", "MiNonPagedPoolBitMap",      // Windows 7, 8 -- not sure, global symbols
        "MiState"                                                                       // Windows 10   -- not sure, global symbols
    ]);

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

    iter = type_information.iter();
    while let Some(typ) = iter.next().unwrap() {
        // type_finder.update(&iter);
        match typ.parse() {
            Ok(TypeData::Class(ClassType {name, fields: Some(fields), ..})) => {
                let n = name.to_string();
                // println!("{}", name);
                if !need_structs.contains_key(&*n) {
                    continue;
                }
                println!("beginstruct {}", name);
                match type_finder.find(fields).unwrap().parse().unwrap() {
                    TypeData::FieldList(list) => {
                        // `fields` is a Vec<TypeData>
                        for field in list.fields {
                            if let TypeData::Member(member) = field {
                                let mem_typ = get_type_as_str(&type_finder, &member.field_type);
                                println!("\t0x{:x} {} {}", member.offset, mem_typ, member.name);
                            } else {
                                println!("\tmember_func");
                                // handle member functions, nested types, etc.
                            }
                        }
                    }
                    _ => {}
                }
                println!("endstruct\n");
            },
            _ => {}
        }
    }
}

fn download_pdb() {
    let mut ntoskrnl = File::open(NTOSKRNL_PATH).expect("Cannot open ntoskrnl.exe");

    let mut buffer = Vec::new();
    ntoskrnl.read_to_end(&mut buffer).expect("Cannot read file ntoskrnl.exe");

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

    let downloadurl = format!("{}/{}/{}{:X}/{}", PDB_SERVER_PATH, PDBNAME, guid, age, PDBNAME);
    println!("{}", downloadurl);

    let mut resp = reqwest::blocking::get(&downloadurl).expect("request failed");
    let mut out = File::create(PDBNAME).expect("failed to create file");
    io::copy(&mut resp, &mut out).expect("failed to copy content");
}

fn main() {
    if !Path::new(PDBNAME).exists() {
        download_pdb();
    }
    parse_pdb();
}

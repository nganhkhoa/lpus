use clap::{App, Arg, SubCommand};
use lpus::{driver_state::DriverState, scan_eprocess};
use std::error::Error;

#[macro_use]
extern crate prettytable;
use prettytable::{Cell, Row, Table};

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Scan CR3")
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .short("p")
                .multiple(true)
                .help("Specify the pids of the processes to display")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("name")
                .long("name")
                .short("n")
                .multiple(true)
                .help("Specify the names of the processes to display")
                .takes_value(true),
        )
        .get_matches();

    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!(
            "Windows version {:?} is not supported",
            driver.windows_ffi.short_version
        )
        .into());
    }
    println!("NtLoadDriver()   -> 0x{:x}", driver.startup());

    let mut proc_list = scan_eprocess(&driver).unwrap_or(Vec::new());

    if matches.is_present("pid") {
        let pid_list: Vec<_> = matches.values_of("pid").unwrap().collect();
        proc_list = proc_list
            .into_iter()
            .filter(|i| pid_list.contains(&(i["pid"].to_string().as_str())))
            .collect();
    }

    if matches.is_present("name") {
        let name_list: Vec<_> = matches.values_of("name").unwrap().collect();
        proc_list = proc_list
            .into_iter()
            .filter(|i| name_list.contains(&(i["name"].as_str().unwrap())))
            .collect();
    }

    let mut result_table = Table::new();
    result_table.add_row(row![
        "Address",
        "Name",
        "pid",
        "ppid",
        "Directory table base"
    ]);

    for p in proc_list {
        result_table.add_row(row![
            p["address"],
            p["name"],
            p["pid"],
            p["ppid"],
            format!("0x{:x}", p["directory_table"].as_u64().unwrap())
        ]);
    }

    //println!("{:?}", proc_list);
    result_table.printstd();
    println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
    Ok(())
}

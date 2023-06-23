use serde_json::json;
use std::error::Error;
use std::fs;
use std::io::Write;

extern crate clap;
extern crate prettytable;
use app_dirs::{app_dir, AppDataType};
use clap::{App, Arg, SubCommand};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "resource"]
struct Asset;

use lpus::{
    commands::{driverscan, modscan, psxview, ssdt, unloadedmodules},
    driver_state::DriverState,
    APP_INFO,
};

fn extract_driver() {
    let driver_bytes = Asset::get("lpus.sys").unwrap();

    let mut driver_location =
        app_dir(AppDataType::UserData, &APP_INFO, &format!("driver")).unwrap();
    driver_location.push("lpus.sys");
    println!("driver location: {:?}", driver_location);

    if let Ok(mut f) = fs::File::create(driver_location) {
        f.write_all(&driver_bytes).unwrap();
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let version = format!(
        "{}-{} commit on {}",
        env!("VERGEN_SEMVER"),
        env!("VERGEN_SHA_SHORT"),
        env!("VERGEN_COMMIT_DATE")
    );
    let matches = App::new("LPUS")
        .version(&*version)
        .author("Khoa Nguyen Anh <mail.nganhkhoa@gmail.com>")
        .about("Live memory fornesics on Windows")
        .arg(
            Arg::with_name("load")
                .short("l")
                .help("Load the driver and exit"),
        )
        .arg(
            Arg::with_name("unload")
                .short("u")
                .help("Unload the driver and exit"),
        )
        .subcommand(
            SubCommand::with_name("repl").about("Run the Interactive REPL (in development)"),
        )
        .subcommand(SubCommand::with_name("pdb").about("Inspect the PDB file"))
        .subcommand(
            SubCommand::with_name("hide_notepad")
                .about("Compare processes found from multiple commands"),
        )
        .subcommand(
            SubCommand::with_name("psxview")
                .about("Compare processes found from multiple commands"),
        )
        .subcommand(
            SubCommand::with_name("unloadedmodules")
                .about("Compare processes found from multiple commands"),
        )
        .subcommand(
            SubCommand::with_name("modscan")
                .about("Compare processes found from multiple commands"),
        )
        .subcommand(
            SubCommand::with_name("driverscan")
                .about("Compare processes found from multiple commands"),
        )
        .subcommand(
            SubCommand::with_name("ssdt")
                .about("Dump the SSDT table")
                .arg(
                    Arg::with_name("hook")
                        .short("h")
                        .help("print only hooked function"),
                ),
        )
        .get_matches();

    extract_driver();
    let mut driver = DriverState::new();
    if !driver.is_supported() {
        return Err(format!(
            "Windows version {:?} is not supported",
            driver.windows_ffi.short_version
        )
        .into());
    }

    if matches.is_present("load") {
        println!("NtLoadDriver()   -> 0x{:x}", driver.startup());
        return Ok(());
    }
    if matches.is_present("unload") {
        println!("NtUnloadDriver() -> 0x{:x}", driver.shutdown());
        return Ok(());
    }

    driver.connect();

    if let Some(_c) = matches.subcommand_matches("hide_notepad") {
        driver.hide_notepad();
        return Ok(());
    }

    if let Some(c) = matches.subcommand_matches("ssdt") {
        ssdt(&driver, c.is_present("hook"));
        return Ok(());
    }

    if let Some(_c) = matches.subcommand_matches("psxview") {
        psxview(&driver);
        return Ok(());
    }

    if let Some(_c) = matches.subcommand_matches("unloadedmodules") {
        unloadedmodules(&driver);
        return Ok(());
    }

    if let Some(_c) = matches.subcommand_matches("driverscan") {
        driverscan(&driver);
        return Ok(());
    }

    if let Some(_c) = matches.subcommand_matches("modscan") {
        modscan(&driver);
        return Ok(());
    }

    Ok(())
}

use std::error::Error;
// use std::time::{SystemTime, UNIX_EPOCH};

use rustyline::error::ReadlineError;
use rustyline::Editor;

use lpus::driver_state::DriverState;

pub fn to_epoch(filetime: u64) -> u64 {
    // https://www.frenk.com/2009/12/convert-filetime-to-unix-timestamp/
    let windows_epoch_diff = 11644473600000 * 10000;
    if filetime < windows_epoch_diff {
        return 0;
    }
    let process_time_epoch = (filetime - windows_epoch_diff) / 10000;
    // let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis() as u64;

    process_time_epoch
}

fn main() -> Result<(), Box<dyn Error>> {
    let driver = DriverState::new();
    driver.windows_ffi.print_version();
    driver.pdb_store.print_default_information();

    println!("{}", to_epoch(0xfffffa80018cb688));
    println!("{}", to_epoch(0x01d64ecd8b295318));

    let mut rl = Editor::<()>::new();
    if rl.load_history("history.lpus").is_err() {
        println!("No previous history.");
    }
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                println!("Line: {}", line);
                // TODO: add parser here
                if let Err(e) = driver.pdb_store.dt(&line) {
                    println!("{}", e);
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    rl.save_history("history.lpus").unwrap();

    Ok(())
}

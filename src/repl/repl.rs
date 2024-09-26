use rustyline::error::ReadlineError;
use rustyline::Editor;

fn repl(e: &mut Lenv) -> Result<()> {
    println!("LPUS v0.0.1");
    println!("Use exit(), Ctrl-C, or Ctrl-D to exit prompt");

    let mut rl = Editor::<()>::new();
    if rl.load_history("./.lpus-history.txt").is_err() {
        println!("No history found.");
    }

    loop {
        let input = rl.readline("lpus> ");

        match input {
            Ok(line) => {
                rl.add_history_entry(line.as_ref());
                print_eval_result(eval_str(e, &line));
            }
            Err(ReadlineError::Interrupted) => {
                info!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                info!("CTRL-D");
                break;
            }
            Err(err) => {
                warn!("Error: {:?}", err);
                break;
            }
        }
    }
    rl.save_history("./.blispr-history.txt")?;
    Ok(())
}

fn print_eval_result(v: ReplResult) {
    match v {
        Ok(res) => println!("{}", res),
        Err(e) => eprintln!("Error: {}", e),
    }
}

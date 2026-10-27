//! Synchronous offline entrypoint: no async runtime, server or configuration.
use std::ffi::OsStr;

fn fail() -> ! {
    eprintln!("inspection_failed");
    std::process::exit(2);
}

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    match (arguments.next(), arguments.next()) {
        (None, None) => (),
        (Some(value), None) if value == OsStr::new("inspect") => (),
        _ => fail(),
    }
    if agentshield::cli::inspect::run(std::io::stdin().lock(), std::io::stdout().lock()).is_err() {
        fail();
    }
}

#![forbid(unsafe_code)]

use std::env;

use dfstl_core::{ExecutionPolicy, SafetyClass};

fn main() {
    let command = env::args().nth(1).unwrap_or_else(|| "help".to_owned());

    match command.as_str() {
        "describe" => describe(),
        "version" | "--version" | "-V" => {
            println!("dfstl {}", env!("CARGO_PKG_VERSION"));
        }
        "help" | "--help" | "-h" => help(),
        other => {
            eprintln!("unknown command: {other}");
            help();
            std::process::exit(2);
        }
    }
}

fn describe() {
    let policy = ExecutionPolicy::default();
    println!("DragonForge Security Test Lab");
    println!("phase: 0");
    println!("default-safety-policy: {}", policy.maximum_class());
    println!(
        "controlled-allowed-by-default: {}",
        policy.allows(SafetyClass::Controlled)
    );
    println!(
        "disruptive-allowed-by-default: {}",
        policy.allows(SafetyClass::Disruptive)
    );
    println!(
        "lab-only-allowed-by-default: {}",
        policy.allows(SafetyClass::LabOnly)
    );
    println!("active-attack-implementations: none");
}

fn help() {
    println!("DragonForge Security Test Lab");
    println!();
    println!("Usage: dfstl <command>");
    println!();
    println!("Commands:");
    println!("  describe   Show the Phase 0 safety/runtime model");
    println!("  version    Show the CLI version");
    println!("  help       Show this help");
}

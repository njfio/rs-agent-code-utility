use clap::Parser;
use rust_tree_sitter::cli::{apply_global_cli_settings, Cli, Execute};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    apply_global_cli_settings(&cli);
    if let Err(e) = cli.command.execute() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    Ok(())
}

use clap::Parser;
use rust_tree_sitter::cli::Execute;

fn main() {
    let cli = rust_tree_sitter::cli::Cli::parse();

    if let Err(e) = cli.command.execute() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

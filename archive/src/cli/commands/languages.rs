//! Languages command implementation

use crate::cli::error::CliResult;
use colored::*;

pub fn execute() -> CliResult<()> {
    println!("\n{}", "🔤 SUPPORTED LANGUAGES".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());

    let languages = crate::supported_languages();

    println!("\n{}", "Language Support Details:".bright_yellow().bold());
    println!("{}", "-".repeat(40));

    for lang in languages {
        println!(
            "  {}: {}",
            lang.name.bright_blue().bold(),
            lang.file_extensions.join(", ")
        );
        println!("    Version: {}", lang.version.bright_white());
        println!();
    }

    println!(
        "\n{}",
        "💡 Usage: Use the language name (lowercase) in commands that require --language parameter"
            .bright_yellow()
    );

    Ok(())
}

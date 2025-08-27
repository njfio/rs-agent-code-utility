//! Languages command implementation

use colored::*;
use tabled::Table;
use crate::cli::error::CliResult;
use crate::cli::output::LanguageRow;

pub fn execute() -> CliResult<()> {
    println!("\n{}", "🔤 SUPPORTED LANGUAGES".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());
    
    let languages = crate::supported_languages();
    let mut language_rows = Vec::new();
    
    for lang in languages {
        language_rows.push(LanguageRow {
            name: lang.name.to_string(),
            files: 0, // Would be calculated from actual usage
            percentage: "N/A".to_string(),
            extensions: lang.file_extensions.join(", "),
        });
    }
    
    let table = Table::new(language_rows);
    println!("\n{}", table);
    
    println!("\n{}", "💡 Usage: Use the language name (lowercase) in commands that require --language parameter".bright_yellow());
    
    Ok(())
}

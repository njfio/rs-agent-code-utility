//! Watch command (scaffold): re-run analysis at intervals.

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use crate::{CodebaseAnalyzer};
use crate::cli::error::{CliError, CliResult, validate_path};
use crate::cli::utils::{create_progress_bar, create_analysis_config};

pub fn execute(path: &PathBuf, interval_secs: u64, max_iterations: usize, depth: &str) -> CliResult<()> {
    validate_path(path)?;
    let pb = create_progress_bar("Watching for changes (scaffold)...");

    let cfg = create_analysis_config(1024, 20, depth, false, None, None, None, false)?;
    let mut analyzer = CodebaseAnalyzer::with_config(cfg)
        .map_err(|e| CliError::Analysis(e.to_string()))?;

    let mut iter = 0usize;
    loop {
        pb.set_message(format!("Analyzing (iteration #{})...", iter + 1));
        let start = std::time::Instant::now();
        let result = analyzer.analyze_directory(path)
            .map_err(|e| CliError::Analysis(e.to_string()))?;
        let dur = start.elapsed();

        println!("[watch] files={} parsed={} errors={} time={:.2?}",
            result.total_files, result.parsed_files, result.error_files, dur);

        iter += 1;
        if max_iterations > 0 && iter >= max_iterations { break; }
        thread::sleep(Duration::from_secs(interval_secs));
    }

    pb.finish_with_message("Watch finished");
    Ok(())
}


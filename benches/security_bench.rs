use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_tree_sitter::{Language, SecurityPipeline};
use std::path::Path;

fn benchmark_security_scanner(c: &mut Criterion) {
    let code = r#"
        fn vulnerable_sql(user_input: &str) {
            let query = format!("SELECT * FROM users WHERE id = {}", user_input);
            execute_query(&query);
        }

        fn vulnerable_command(user_input: &str) {
            std::process::Command::new(user_input);
        }
    "#;
    let pipeline = SecurityPipeline::new()
        .unwrap_or_else(|err| panic!("failed to create security pipeline for benchmark: {}", err));
    let file_path = Path::new("bench_inputs/security_sample.rs");

    c.bench_function("security_scan_small_file", |b| {
        b.iter(|| {
            black_box(
                pipeline
                    .analyze_with_path(black_box(code), file_path, Language::Rust)
                    .unwrap_or_else(|err| {
                        panic!("security benchmark analysis failed unexpectedly: {}", err)
                    }),
            );
        })
    });
}

criterion_group!(security_benches, benchmark_security_scanner);
criterion_main!(security_benches);

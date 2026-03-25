use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rust_tree_sitter::{Language, Parser};

fn benchmark_rust_parser(c: &mut Criterion) {
    let code = include_str!("../src/lib.rs");

    c.bench_function("parse_rust_file", |b| {
        b.iter_batched_ref(
            || {
                Parser::new(Language::Rust)
                    .unwrap_or_else(|err| panic!("failed to create Rust parser: {err}"))
            },
            |parser| {
                black_box(
                    parser.parse(black_box(code), None).unwrap_or_else(|err| {
                        panic!("failed to parse Rust benchmark input: {err}")
                    }),
                );
            },
            BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "extended-languages")]
fn benchmark_javascript_parser(c: &mut Criterion) {
    let code = r#"
        function fibonacci(n) {
            if (n <= 1) return n;
            return fibonacci(n - 1) + fibonacci(n - 2);
        }
        console.log(fibonacci(10));
    "#;

    c.bench_function("parse_javascript", |b| {
        b.iter_batched_ref(
            || {
                Parser::new(Language::JavaScript)
                    .unwrap_or_else(|err| panic!("failed to create JavaScript parser: {err}"))
            },
            |parser| {
                black_box(parser.parse(black_box(code), None).unwrap_or_else(|err| {
                    panic!("failed to parse JavaScript benchmark input: {err}")
                }));
            },
            BatchSize::SmallInput,
        )
    });
}

#[cfg(feature = "extended-languages")]
criterion_group!(benches, benchmark_rust_parser, benchmark_javascript_parser);
#[cfg(not(feature = "extended-languages"))]
criterion_group!(benches, benchmark_rust_parser);
criterion_main!(benches);

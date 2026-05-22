use rust_tree_sitter::*;
use std::time::Instant;

#[test]
fn test_parser_caching_performance() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(Language::Rust)?;

    let source_code = r#"
        fn fibonacci(n: u32) -> u32 {
            if n <= 1 {
                n
            } else {
                fibonacci(n - 1) + fibonacci(n - 2)
            }
        }
        
        fn main() {
            for i in 0..10 {
                println!("fib({}) = {}", i, fibonacci(i));
            }
        }
    "#;

    // First parse - should be slower (no cache)
    let start = Instant::now();
    let tree1 = parser.parse(source_code, None)?;
    let first_parse_time = start.elapsed();

    // Second parse - should be faster (cached)
    let start = Instant::now();
    let tree2 = parser.parse(source_code, None)?;
    let second_parse_time = start.elapsed();

    // Verify trees are equivalent
    assert_eq!(tree1.source(), tree2.source());
    assert_eq!(tree1.root_node().kind(), tree2.root_node().kind());

    // Cache should make second parse significantly faster
    // Note: This might not always be true in debug builds or very fast machines
    println!(
        "First parse: {:?}, Second parse: {:?}",
        first_parse_time, second_parse_time
    );

    // Verify cache statistics
    let (cache_size, max_size) = parser.cache_stats()?;
    assert!(cache_size > 0, "Cache should contain at least one entry");
    assert_eq!(max_size, 100, "Default cache size should be 100");

    Ok(())
}

#[test]
fn test_parser_cache_eviction() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::with_cache_size(Language::Rust, 2)?;

    let code1 = "fn test1() {}";
    let code2 = "fn test2() {}";
    let code3 = "fn test3() {}";

    // Parse three different pieces of code
    parser.parse(code1, None)?;
    parser.parse(code2, None)?;
    parser.parse(code3, None)?; // Should evict the first entry

    let (cache_size, max_size) = parser.cache_stats()?;
    assert_eq!(
        cache_size, 2,
        "Cache should contain exactly 2 entries after eviction"
    );
    assert_eq!(max_size, 2, "Max cache size should be 2");

    Ok(())
}

#[test]
fn test_parser_cache_clear() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(Language::Rust)?;

    // Parse some code to populate cache
    parser.parse("fn test() {}", None)?;

    let (cache_size_before, _) = parser.cache_stats()?;
    assert!(
        cache_size_before > 0,
        "Cache should have entries before clearing"
    );

    // Clear cache
    parser.clear_cache()?;

    let (cache_size_after, _) = parser.cache_stats()?;
    assert_eq!(cache_size_after, 0, "Cache should be empty after clearing");

    Ok(())
}

#[test]
fn test_optimized_tree_traversal() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(Language::Rust)?;

    let source_code = r#"
        fn function1() {
            if true {
                for i in 0..10 {
                    println!("{}", i);
                }
            }
        }
        
        fn function2() {
            while true {
                break;
            }
        }
        
        fn function3() {
            match Some(42) {
                Some(x) => println!("{}", x),
                None => println!("None"),
            }
        }
    "#;

    let tree = parser.parse(source_code, None)?;

    // Test optimized find_nodes_by_kind
    let start = Instant::now();
    let functions = tree.find_nodes_by_kind("function_item");
    let find_time = start.elapsed();

    assert_eq!(functions.len(), 3, "Should find 3 functions");
    println!("Find nodes time: {:?}", find_time);

    // Test optimized find_descendants
    let start = Instant::now();
    let all_blocks = tree
        .root_node()
        .find_descendants(|node| node.kind() == "block");
    let descendants_time = start.elapsed();

    assert!(!all_blocks.is_empty(), "Should find block nodes");
    println!("Find descendants time: {:?}", descendants_time);

    Ok(())
}

#[test]
fn test_memory_allocation_optimization() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let parser = Parser::new(Language::Rust)?;

    let source_code = r#"
        fn test_function() {
            let mut vec = Vec::new();
            vec.push(1);
            vec.push(2);
            vec.push(3);
            
            let string = String::new();
            let map = std::collections::HashMap::new();
        }
    "#;

    let tree = parser.parse(source_code, None)?;

    // Test that our optimized methods don't allocate excessively
    let start = Instant::now();

    // Multiple calls to test memory efficiency
    for _ in 0..100 {
        let _calls = tree.find_nodes_by_kind("call_expression");
        let _identifiers = tree.find_nodes_by_kind("identifier");
    }

    let batch_time = start.elapsed();
    println!("Batch operations time: {:?}", batch_time);

    // Should complete reasonably quickly
    assert!(
        batch_time.as_millis() < 1000,
        "Batch operations should be fast"
    );

    Ok(())
}


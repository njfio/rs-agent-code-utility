use rust_tree_sitter::{
    MemoryTracker, MemoryTrackingConfig, AnalysisResult, FileInfo,
    AllocationType, LeakType, UsagePattern
};
use std::path::PathBuf;
use std::collections::HashMap;

fn create_test_analysis_result(code: &str, language: &str, filename: &str) -> AnalysisResult {
    let file_info = FileInfo {
        path: PathBuf::from(filename),
        language: language.to_string(),
        size: code.len(),
        lines: code.lines().count(),
        parsed_successfully: true,
        parse_errors: vec![],
        symbols: vec![],
        security_vulnerabilities: vec![],
    };

    let mut languages = HashMap::new();
    languages.insert(language.to_string(), 1);

    AnalysisResult {
        root_path: PathBuf::from("."),
        total_files: 1,
        parsed_files: 1,
        error_files: 0,
        total_lines: code.lines().count(),
        languages,
        files: vec![file_info],
        config: rust_tree_sitter::AnalysisConfig::default(),
    }
}

#[test]
fn test_memory_tracker_creation() {
    let tracker = MemoryTracker::new();
    let stats = tracker.get_statistics();
    
    assert_eq!(stats.total_allocations, 0);
    assert_eq!(stats.total_deallocations, 0);
    assert_eq!(stats.current_bytes_in_use, 0);
}

#[test]
fn test_memory_tracker_with_config() {
    let config = MemoryTrackingConfig {
        track_heap_allocations: true,
        track_stack_allocations: true,
        detect_memory_leaks: true,
        track_allocation_patterns: true,
        track_fragmentation: true,
        min_allocation_size: 64,
        max_call_stack_depth: 15,
        real_time_tracking: true,
    };
    
    let tracker = MemoryTracker::with_config(config.clone());
    assert_eq!(tracker.get_config().min_allocation_size, 64);
    assert_eq!(tracker.get_config().max_call_stack_depth, 15);
    assert!(tracker.get_config().real_time_tracking);
}

#[test]
fn test_rust_allocation_detection() {
    let mut tracker = MemoryTracker::new();
    
    // Create a mock analysis result with Rust code
    let rust_code = r#"
fn main() {
    let mut vec = Vec::new();
    for i in 0..1000 {
        vec.push(i);
        let s = String::new();
        let map = HashMap::new();
    }
    
    let boxed = Box::new(42);
    let capacity_vec = Vec::with_capacity(100);
}
"#;
    
    let analysis_result = create_test_analysis_result(rust_code, "rust", "test.rs");
    
    // Write the test file
    std::fs::write("test.rs", rust_code).unwrap();
    
    let result = tracker.analyze_memory_allocations(&analysis_result).unwrap();
    
    // Clean up
    std::fs::remove_file("test.rs").ok();
    
    // Verify allocation hotspots were detected
    assert!(!result.allocation_hotspots.is_empty());
    
    // Check for specific allocation types
    let has_vec_allocation = result.allocation_hotspots.iter()
        .any(|h| h.allocation_type == AllocationType::VectorAllocation);
    let has_string_allocation = result.allocation_hotspots.iter()
        .any(|h| h.allocation_type == AllocationType::StringAllocation);
    let has_box_allocation = result.allocation_hotspots.iter()
        .any(|h| h.allocation_type == AllocationType::HeapAllocation);
    
    assert!(has_vec_allocation, "Should detect Vec allocations");
    assert!(has_string_allocation, "Should detect String allocations");
    assert!(has_box_allocation, "Should detect Box allocations");
}

#[test]
fn test_memory_leak_detection() {
    let mut tracker = MemoryTracker::new();
    
    // Rust code with potential memory leaks
    let rust_code = r#"
use std::rc::Rc;
use std::cell::RefCell;

fn create_cycle() {
    let a = Rc::new(RefCell::new(None));
    let b = Rc::new(RefCell::new(Some(a.clone())));
    *a.borrow_mut() = Some(b.clone());
}

fn explicit_leak() {
    let data = Box::new(vec![1, 2, 3, 4, 5]);
    Box::leak(data);
}

fn forget_memory() {
    let data = Box::new("important data");
    std::mem::forget(data);
}
"#;
    
    let analysis_result = create_test_analysis_result(rust_code, "rust", "leak_test.rs");
    
    // Write the test file
    std::fs::write("leak_test.rs", rust_code).unwrap();
    
    let result = tracker.analyze_memory_allocations(&analysis_result).unwrap();
    
    // Clean up
    std::fs::remove_file("leak_test.rs").ok();
    
    // Verify leak candidates were detected
    assert!(!result.leak_candidates.is_empty());
    
    // Check for specific leak types
    let has_reference_cycle = result.leak_candidates.iter()
        .any(|l| l.leak_type == LeakType::ReferenceCycle);
    let has_direct_leak = result.leak_candidates.iter()
        .any(|l| l.leak_type == LeakType::DirectLeak);
    
    assert!(has_reference_cycle, "Should detect reference cycles");
    assert!(has_direct_leak, "Should detect explicit leaks");
}

#[test]
fn test_cpp_allocation_detection() {
    let mut tracker = MemoryTracker::new();
    
    let cpp_code = r#"
#include <iostream>
#include <vector>

int main() {
    for (int i = 0; i < 1000; ++i) {
        int* ptr = new int(i);
        char* buffer = (char*)malloc(1024);
        
        std::vector<int> vec;
        vec.push_back(i);
        
        // Missing delete and free - potential leaks
    }
    return 0;
}
"#;
    
    let analysis_result = create_test_analysis_result(cpp_code, "cpp", "test.cpp");
    
    // Write the test file
    std::fs::write("test.cpp", cpp_code).unwrap();
    
    let result = tracker.analyze_memory_allocations(&analysis_result).unwrap();
    
    // Clean up
    std::fs::remove_file("test.cpp").ok();
    
    // Verify allocations and potential leaks were detected
    assert!(!result.allocation_hotspots.is_empty());
    assert!(!result.leak_candidates.is_empty());
    
    // Check for heap allocations
    let has_heap_allocation = result.allocation_hotspots.iter()
        .any(|h| h.allocation_type == AllocationType::HeapAllocation);
    
    assert!(has_heap_allocation, "Should detect heap allocations");
}

#[test]
fn test_allocation_patterns() {
    let mut tracker = MemoryTracker::new();
    
    let rust_code = r#"
fn process_data() {
    let mut results = Vec::new();
    for item in data.iter() {
        let processed = String::from(item);
        results.push(processed);
    }
}

fn create_lookup_table() {
    let mut table = HashMap::new();
    for i in 0..1000 {
        table.insert(i, format!("value_{}", i));
    }
}
"#;
    
    let analysis_result = create_test_analysis_result(rust_code, "rust", "patterns.rs");
    
    // Write the test file
    std::fs::write("patterns.rs", rust_code).unwrap();
    
    let result = tracker.analyze_memory_allocations(&analysis_result).unwrap();
    
    // Clean up
    std::fs::remove_file("patterns.rs").ok();
    
    // Verify allocation patterns were detected
    assert!(!result.allocation_patterns.is_empty());
    
    // Check for specific usage patterns
    let has_growing_collections = result.allocation_patterns.iter()
        .any(|p| p.usage_pattern == UsagePattern::GrowingCollections);
    let has_frequent_churn = result.allocation_patterns.iter()
        .any(|p| p.usage_pattern == UsagePattern::FrequentChurn);
    
    assert!(has_growing_collections || has_frequent_churn, "Should detect allocation patterns");
}

#[test]
fn test_memory_statistics() {
    let tracker = MemoryTracker::new();
    let stats = tracker.get_statistics();
    
    // Test initial state
    assert_eq!(stats.total_allocations, 0);
    assert_eq!(stats.total_deallocations, 0);
    assert_eq!(stats.active_allocations, 0);
    assert_eq!(stats.current_bytes_in_use, 0);
    assert_eq!(stats.allocation_rate, 0.0);
    assert_eq!(stats.deallocation_rate, 0.0);
}

#[test]
fn test_fragmentation_analysis() {
    let mut tracker = MemoryTracker::new();
    
    // Code with many small allocations (potential fragmentation)
    let rust_code = r#"
fn fragment_memory() {
    for i in 0..10000 {
        let small_vec = vec![i; 4]; // Small allocations
        let tiny_string = format!("{}", i); // More small allocations
    }
}
"#;
    
    let analysis_result = create_test_analysis_result(rust_code, "rust", "fragment.rs");
    
    // Write the test file
    std::fs::write("fragment.rs", rust_code).unwrap();
    
    let result = tracker.analyze_memory_allocations(&analysis_result).unwrap();
    
    // Clean up
    std::fs::remove_file("fragment.rs").ok();
    
    // Verify fragmentation analysis
    assert!(result.fragmentation_analysis.fragmentation_percentage >= 0.0);
    assert!(result.fragmentation_analysis.fragmentation_percentage <= 100.0);
}

#[test]
fn test_call_stack_analysis() {
    let mut tracker = MemoryTracker::new();
    
    let rust_code = r#"
fn allocate_data() -> Vec<i32> {
    Vec::with_capacity(1000)
}

fn process_items() {
    let data = allocate_data();
    for item in data {
        let result = String::from("processed");
    }
}

fn main() {
    process_items();
}
"#;
    
    let analysis_result = create_test_analysis_result(rust_code, "rust", "callstack.rs");
    
    // Write the test file
    std::fs::write("callstack.rs", rust_code).unwrap();
    
    let result = tracker.analyze_memory_allocations(&analysis_result).unwrap();
    
    // Clean up
    std::fs::remove_file("callstack.rs").ok();
    
    // Verify call stack analysis
    assert!(!result.call_stacks.is_empty());
    
    // Check that call stacks have frames
    let has_frames = result.call_stacks.iter()
        .any(|cs| !cs.frames.is_empty());
    
    assert!(has_frames, "Call stacks should have frames");
}

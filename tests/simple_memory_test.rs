use rust_tree_sitter::{MemoryTracker, MemoryTrackingConfig};

#[test]
fn test_memory_tracker_basic() {
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

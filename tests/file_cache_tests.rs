use rust_tree_sitter::FileCache;
use tempfile::TempDir;
use std::fs;

/// Test basic file cache creation
#[test]
fn test_file_cache_creation() {
    let cache = FileCache::new();
    
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
    assert_eq!(cache.hit_ratio(), 0.0);
}

/// Test file cache with custom capacity
#[test]
fn test_file_cache_with_capacity() {
    let cache = FileCache::with_capacity(500);
    
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

/// Test reading file content and caching
#[test]
fn test_read_to_string_and_caching() -> Result<(), Box<dyn std::error::Error>> {
    let cache = FileCache::new();
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    
    let content = "Hello, world!";
    fs::write(&test_file, content)?;
    
    // File should not be cached initially
    assert!(!cache.contains(&test_file));
    assert_eq!(cache.len(), 0);
    
    // Read file content (should cache it)
    let read_content = cache.read_to_string(&test_file)?;
    assert_eq!(read_content, content);
    
    // File should now be cached
    assert!(cache.contains(&test_file));
    assert_eq!(cache.len(), 1);
    
    // Read again (should hit cache)
    let read_content2 = cache.read_to_string(&test_file)?;
    assert_eq!(read_content2, content);
    
    Ok(())
}

/// Test cache statistics
#[test]
fn test_cache_statistics() -> Result<(), Box<dyn std::error::Error>> {
    let cache = FileCache::new();
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    
    fs::write(&test_file, "Test content")?;
    
    // Initial stats
    let initial_stats = cache.stats();
    assert_eq!(initial_stats.hits, 0);
    assert_eq!(initial_stats.misses, 0);
    assert_eq!(initial_stats.cached_files, 0);
    
    // Read file (should be a miss)
    cache.read_to_string(&test_file)?;
    
    let stats_after_miss = cache.stats();
    assert_eq!(stats_after_miss.hits, 0);
    assert_eq!(stats_after_miss.misses, 1);
    assert_eq!(stats_after_miss.cached_files, 1);
    
    // Read again (should be a hit)
    cache.read_to_string(&test_file)?;
    
    let stats_after_hit = cache.stats();
    assert_eq!(stats_after_hit.hits, 1);
    assert_eq!(stats_after_hit.misses, 1);
    assert_eq!(stats_after_hit.cached_files, 1);
    
    Ok(())
}

/// Test cache hit ratio calculation
#[test]
fn test_hit_ratio() -> Result<(), Box<dyn std::error::Error>> {
    let cache = FileCache::new();
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    
    fs::write(&test_file, "Test content")?;
    
    // Initial hit ratio should be 0.0
    assert_eq!(cache.hit_ratio(), 0.0);
    
    // Read file once (miss)
    cache.read_to_string(&test_file)?;
    assert_eq!(cache.hit_ratio(), 0.0); // 0 hits, 1 miss = 0%
    
    // Read file again (hit)
    cache.read_to_string(&test_file)?;
    assert_eq!(cache.hit_ratio(), 0.5); // 1 hit, 1 miss = 50%
    
    // Read file again (another hit)
    cache.read_to_string(&test_file)?;
    assert!((cache.hit_ratio() - 0.6667).abs() < 0.001); // 2 hits, 1 miss ≈ 66.67%
    
    Ok(())
}

/// Test cache clearing
#[test]
fn test_cache_clear() -> Result<(), Box<dyn std::error::Error>> {
    let cache = FileCache::new();
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    
    fs::write(&test_file, "Test content")?;
    
    // Cache a file
    cache.read_to_string(&test_file)?;
    assert_eq!(cache.len(), 1);
    assert!(cache.contains(&test_file));
    
    // Clear cache
    cache.clear();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
    assert!(!cache.contains(&test_file));
    
    Ok(())
}

/// Test cache with multiple files
#[test]
fn test_multiple_files() -> Result<(), Box<dyn std::error::Error>> {
    let cache = FileCache::new();
    let temp_dir = TempDir::new()?;
    
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let file3 = temp_dir.path().join("file3.txt");
    
    fs::write(&file1, "Content 1")?;
    fs::write(&file2, "Content 2")?;
    fs::write(&file3, "Content 3")?;
    
    // Cache all files
    let content1 = cache.read_to_string(&file1)?;
    let content2 = cache.read_to_string(&file2)?;
    let content3 = cache.read_to_string(&file3)?;
    
    assert_eq!(content1, "Content 1");
    assert_eq!(content2, "Content 2");
    assert_eq!(content3, "Content 3");
    
    // All files should be cached
    assert_eq!(cache.len(), 3);
    assert!(cache.contains(&file1));
    assert!(cache.contains(&file2));
    assert!(cache.contains(&file3));
    
    // Stats should show 3 misses, 0 hits
    let stats = cache.stats();
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 3);
    assert_eq!(stats.cached_files, 3);
    
    Ok(())
}

/// Test cache efficiency calculation
#[test]
fn test_cache_efficiency() -> Result<(), Box<dyn std::error::Error>> {
    let cache = FileCache::new();
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    
    fs::write(&test_file, "Test content")?;
    
    // Read file multiple times to build up hits
    cache.read_to_string(&test_file)?; // miss
    cache.read_to_string(&test_file)?; // hit
    cache.read_to_string(&test_file)?; // hit
    
    let stats = cache.stats();
    let efficiency = stats.efficiency();
    
    // Should be 2 hits out of 3 total = 66.67%
    assert!((efficiency - 66.67).abs() < 0.01);
    
    Ok(())
}

/// Test average file size calculation
#[test]
fn test_average_file_size() -> Result<(), Box<dyn std::error::Error>> {
    let cache = FileCache::new();
    let temp_dir = TempDir::new()?;
    
    let file1 = temp_dir.path().join("small.txt");
    let file2 = temp_dir.path().join("large.txt");
    
    fs::write(&file1, "Hi")?; // 2 bytes
    fs::write(&file2, "Hello, world!")?; // 13 bytes
    
    // Cache both files
    cache.read_to_string(&file1)?;
    cache.read_to_string(&file2)?;
    
    let stats = cache.stats();
    let avg_size = stats.average_file_size();
    
    // Average should be (2 + 13) / 2 = 7.5 bytes
    assert!((avg_size - 7.5).abs() < 0.1);
    
    Ok(())
}

/// Test cache behavior with non-existent files
#[test]
fn test_nonexistent_file() {
    let cache = FileCache::new();
    let nonexistent_path = "/path/that/does/not/exist.txt";

    // Should return an error, not panic
    let result = cache.read_to_string(nonexistent_path);
    assert!(result.is_err());

    // Cache should remain empty
    assert_eq!(cache.len(), 0);
    assert!(!cache.contains(nonexistent_path));
}

/// Test cache is_empty functionality
#[test]
fn test_is_empty() -> Result<(), Box<dyn std::error::Error>> {
    let cache = FileCache::new();

    // Initially empty
    assert!(cache.is_empty());

    // Add a file
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, "content")?;

    cache.read_to_string(&test_file)?;

    // Should not be empty
    assert!(!cache.is_empty());

    // Clear and check again
    cache.clear();
    assert!(cache.is_empty());

    Ok(())
}

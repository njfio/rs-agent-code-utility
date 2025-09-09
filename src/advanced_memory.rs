//! Advanced memory management system for rust_tree_sitter
//!
//! This module provides sophisticated memory management capabilities including:
//! - Memory-mapped file support for large files
//! - Streaming analysis for files exceeding memory thresholds
//! - Memory pool management for efficient allocation
//! - Memory usage tracking and reporting
//! - Garbage collection hints for long-running processes
//! - Memory pressure monitoring and optimization

use crate::error::{Error, Result};
use memmap2::{Mmap, MmapOptions};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for memory management
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// Maximum memory usage for analysis (bytes)
    pub max_memory_bytes: usize,
    /// File size threshold for streaming analysis (bytes)
    pub streaming_threshold_bytes: usize,
    /// Chunk size for streaming analysis (bytes)
    pub chunk_size_bytes: usize,
    /// Enable memory-mapped files
    pub enable_memory_mapping: bool,
    /// Memory pool size for object reuse
    pub memory_pool_size: usize,
    /// Memory pressure check interval
    pub pressure_check_interval: Duration,
    /// GC hint threshold (percentage of max memory)
    pub gc_hint_threshold_percent: u8,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 512 * 1024 * 1024,         // 512MB
            streaming_threshold_bytes: 50 * 1024 * 1024, // 50MB
            chunk_size_bytes: 1024 * 1024,               // 1MB chunks
            enable_memory_mapping: true,
            memory_pool_size: 10 * 1024 * 1024, // 10MB pool
            pressure_check_interval: Duration::from_secs(5),
            gc_hint_threshold_percent: 80,
        }
    }
}

/// Memory usage statistics
#[derive(Debug, Clone, Default)]
pub struct MemoryStats {
    pub current_usage_bytes: usize,
    pub peak_usage_bytes: usize,
    pub allocations_count: u64,
    pub deallocations_count: u64,
    pub memory_mapped_files: usize,
    pub streaming_chunks_processed: u64,
    pub gc_cycles: u64,
    pub memory_pressure_events: u64,
}

/// Memory-mapped file wrapper with safe access
pub struct MemoryMappedFile {
    mmap: Mmap,
    file_size: usize,
    _path: std::path::PathBuf,
}

impl MemoryMappedFile {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(&path).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to open file for memory mapping: {}",
                e
            )))
        })?;

        let metadata = file.metadata().map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to get file metadata: {}",
                e
            )))
        })?;

        let file_size = metadata.len() as usize;

        // Memory map the file
        let mmap = unsafe {
            MmapOptions::new().map(&file).map_err(|e| {
                Error::IoError(std::io::Error::other(format!(
                    "Failed to memory map file: {}",
                    e
                )))
            })?
        };

        Ok(Self {
            mmap,
            file_size,
            _path: path.as_ref().to_path_buf(),
        })
    }

    /// Get the file size
    pub fn size(&self) -> usize {
        self.file_size
    }

    /// Get a slice of the memory-mapped data
    pub fn as_slice(&self) -> &[u8] {
        &self.mmap
    }

    /// Read data from a specific offset
    pub fn read_at(&self, offset: usize, len: usize) -> Result<&[u8]> {
        if offset + len > self.file_size {
            return Err(Error::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Read beyond file bounds",
            )));
        }
        Ok(&self.mmap[offset..offset + len])
    }

    /// Check if the file is suitable for memory mapping
    pub fn is_suitable_for_mapping(file_size: u64) -> bool {
        // Don't memory map files larger than 1GB to avoid excessive memory usage
        file_size <= 1024 * 1024 * 1024
    }
}

/// Streaming file reader for large files
pub struct StreamingFileReader {
    reader: BufReader<File>,
    buffer: Vec<u8>,
    chunk_size: usize,
    total_read: usize,
    file_size: usize,
}

impl StreamingFileReader {
    pub fn new<P: AsRef<Path>>(path: P, chunk_size: usize) -> Result<Self> {
        let file = File::open(&path).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to open file for streaming: {}",
                e
            )))
        })?;

        let metadata = file.metadata().map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to get file metadata: {}",
                e
            )))
        })?;

        let file_size = metadata.len() as usize;
        let reader = BufReader::new(file);

        Ok(Self {
            reader,
            buffer: vec![0; chunk_size],
            chunk_size,
            total_read: 0,
            file_size,
        })
    }

    /// Read the next chunk of data
    pub fn read_chunk(&mut self) -> Result<Option<&[u8]>> {
        let bytes_read = self.reader.read(&mut self.buffer).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to read chunk: {}",
                e
            )))
        })?;

        if bytes_read == 0 {
            return Ok(None); // EOF
        }

        self.total_read += bytes_read;
        Ok(Some(&self.buffer[..bytes_read]))
    }

    /// Seek to a specific position
    pub fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.reader
            .seek(pos)
            .map_err(|e| Error::IoError(std::io::Error::other(format!("Failed to seek: {}", e))))
    }

    /// Get current position
    pub fn position(&mut self) -> Result<u64> {
        self.reader.stream_position().map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to get position: {}",
                e
            )))
        })
    }

    /// Get total file size
    pub fn file_size(&self) -> usize {
        self.file_size
    }

    /// Get total bytes read so far
    pub fn total_read(&self) -> usize {
        self.total_read
    }

    /// Check if we've reached EOF
    pub fn is_eof(&self) -> bool {
        self.total_read >= self.file_size
    }

    /// Get the chunk size used for reading
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }
}

/// Memory pool for efficient object reuse
pub struct MemoryPool<T: Default + Clone> {
    pool: Mutex<Vec<T>>,
    max_size: usize,
    stats: Arc<Mutex<PoolStats>>,
}

impl<T: Default + Clone> Clone for MemoryPool<T> {
    fn clone(&self) -> Self {
        Self {
            pool: Mutex::new(Vec::new()), // Start with empty pool for cloned instance
            max_size: self.max_size,
            stats: Arc::new(Mutex::new(PoolStats::default())), // Fresh stats for cloned instance
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    allocations: u64,
    deallocations: u64,
    hits: u64,
    misses: u64,
}

impl<T: Default + Clone> MemoryPool<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            pool: Mutex::new(Vec::with_capacity(max_size)),
            max_size,
            stats: Arc::new(Mutex::new(PoolStats::default())),
        }
    }

    /// Get an object from the pool or create a new one
    pub fn get(&self) -> T {
        let mut pool = self.pool.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();

        if let Some(obj) = pool.pop() {
            stats.hits += 1;
            obj
        } else {
            stats.misses += 1;
            stats.allocations += 1;
            T::default()
        }
    }

    /// Return an object to the pool for reuse
    pub fn put(&self, obj: T) {
        let mut pool = self.pool.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();

        if pool.len() < self.max_size {
            pool.push(obj);
            stats.deallocations += 1;
        }
        // If pool is full, object is dropped
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        self.stats.lock().unwrap().clone()
    }
}

/// Garbage collection hints provider
pub struct GarbageCollector {
    last_gc_hint: Arc<Mutex<Instant>>,
    gc_threshold_bytes: usize,
    memory_tracker: Arc<MemoryTracker>,
}

impl GarbageCollector {
    pub fn new(memory_tracker: Arc<MemoryTracker>, gc_threshold_bytes: usize) -> Self {
        Self {
            last_gc_hint: Arc::new(Mutex::new(Instant::now())),
            gc_threshold_bytes,
            memory_tracker,
        }
    }

    /// Check if GC should be triggered and provide hints
    pub fn should_collect_garbage(&self) -> Result<Option<GCHint>> {
        let current_usage = self.memory_tracker.current_usage.load(Ordering::Relaxed);

        if current_usage >= self.gc_threshold_bytes {
            let mut last_hint = self.last_gc_hint.lock().unwrap();
            let now = Instant::now();

            // Don't spam GC hints too frequently
            if now.duration_since(*last_hint) > Duration::from_secs(10) {
                *last_hint = now;

                let hint = GCHint {
                    reason: GCReason::MemoryPressure,
                    recommended_action: GCAction::FullCollection,
                    estimated_memory_reclaimable: current_usage
                        .saturating_sub(self.gc_threshold_bytes / 2),
                };

                return Ok(Some(hint));
            }
        }

        Ok(None)
    }

    /// Force a garbage collection cycle
    pub fn force_collection(&self) -> Result<()> {
        // In a real implementation, this would trigger actual GC
        // For now, just update the hint timestamp
        let mut last_hint = self.last_gc_hint.lock().unwrap();
        *last_hint = Instant::now();
        Ok(())
    }
}

/// Garbage collection hint
#[derive(Debug, Clone)]
pub struct GCHint {
    pub reason: GCReason,
    pub recommended_action: GCAction,
    pub estimated_memory_reclaimable: usize,
}

/// Reason for triggering garbage collection
#[derive(Debug, Clone)]
pub enum GCReason {
    MemoryPressure,
    IdleTime,
    ExplicitRequest,
}

/// Recommended garbage collection action
#[derive(Debug, Clone)]
pub enum GCAction {
    MinorCollection,
    MajorCollection,
    FullCollection,
}

/// Memory usage tracker
pub struct MemoryTracker {
    current_usage: AtomicUsize,
    peak_usage: AtomicUsize,
    allocations: AtomicUsize,
    deallocations: AtomicUsize,
    memory_mapped_files: AtomicUsize,
    streaming_chunks: AtomicUsize,
    gc_cycles: AtomicUsize,
    pressure_events: AtomicUsize,
}

impl MemoryTracker {
    pub fn new() -> Self {
        Self {
            current_usage: AtomicUsize::new(0),
            peak_usage: AtomicUsize::new(0),
            allocations: AtomicUsize::new(0),
            deallocations: AtomicUsize::new(0),
            memory_mapped_files: AtomicUsize::new(0),
            streaming_chunks: AtomicUsize::new(0),
            gc_cycles: AtomicUsize::new(0),
            pressure_events: AtomicUsize::new(0),
        }
    }

    /// Record memory allocation
    pub fn record_allocation(&self, bytes: usize) {
        let current = self.current_usage.fetch_add(bytes, Ordering::Relaxed);
        let new_total = current + bytes;

        // Update peak usage
        let mut peak = self.peak_usage.load(Ordering::Relaxed);
        while new_total > peak {
            match self.peak_usage.compare_exchange_weak(
                peak,
                new_total,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current_peak) => peak = current_peak,
            }
        }

        self.allocations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record memory deallocation
    pub fn record_deallocation(&self, bytes: usize) {
        self.current_usage.fetch_sub(bytes, Ordering::Relaxed);
        self.deallocations.fetch_add(1, Ordering::Relaxed);
    }

    /// Record memory mapped file creation
    pub fn record_memory_mapped_file(&self) {
        self.memory_mapped_files.fetch_add(1, Ordering::Relaxed);
    }

    /// Record streaming chunk processing
    pub fn record_streaming_chunk(&self) {
        self.streaming_chunks.fetch_add(1, Ordering::Relaxed);
    }

    /// Record garbage collection cycle
    pub fn record_gc_cycle(&self) {
        self.gc_cycles.fetch_add(1, Ordering::Relaxed);
    }

    /// Record memory pressure event
    pub fn record_pressure_event(&self) {
        self.pressure_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current memory usage
    pub fn current_usage(&self) -> usize {
        self.current_usage.load(Ordering::Relaxed)
    }

    /// Get peak memory usage
    pub fn peak_usage(&self) -> usize {
        self.peak_usage.load(Ordering::Relaxed)
    }

    /// Get memory statistics
    pub fn stats(&self) -> MemoryStats {
        MemoryStats {
            current_usage_bytes: self.current_usage.load(Ordering::Relaxed),
            peak_usage_bytes: self.peak_usage.load(Ordering::Relaxed),
            allocations_count: self.allocations.load(Ordering::Relaxed) as u64,
            deallocations_count: self.deallocations.load(Ordering::Relaxed) as u64,
            memory_mapped_files: self.memory_mapped_files.load(Ordering::Relaxed),
            streaming_chunks_processed: self.streaming_chunks.load(Ordering::Relaxed) as u64,
            gc_cycles: self.gc_cycles.load(Ordering::Relaxed) as u64,
            memory_pressure_events: self.pressure_events.load(Ordering::Relaxed) as u64,
        }
    }
}

impl Default for MemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Advanced memory manager that coordinates all memory management features
pub struct AdvancedMemoryManager {
    config: MemoryConfig,
    tracker: Arc<MemoryTracker>,
    gc: GarbageCollector,
    memory_pools: HashMap<String, Box<dyn std::any::Any + Send + Sync>>,
}

impl AdvancedMemoryManager {
    pub fn new(config: MemoryConfig) -> Self {
        let tracker = Arc::new(MemoryTracker::new());
        let gc = GarbageCollector::new(
            Arc::clone(&tracker),
            config.gc_hint_threshold_percent as usize * config.max_memory_bytes / 100,
        );

        Self {
            config,
            tracker,
            gc,
            memory_pools: HashMap::new(),
        }
    }

    /// Decide whether to use streaming or memory-mapped analysis for a file
    pub fn choose_analysis_strategy<P: AsRef<Path>>(
        &self,
        file_path: P,
    ) -> Result<AnalysisStrategy> {
        let metadata = std::fs::metadata(&file_path).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to get file metadata: {}",
                e
            )))
        })?;

        let file_size = metadata.len() as usize;

        if file_size >= self.config.streaming_threshold_bytes {
            Ok(AnalysisStrategy::Streaming)
        } else if self.config.enable_memory_mapping
            && MemoryMappedFile::is_suitable_for_mapping(metadata.len())
        {
            Ok(AnalysisStrategy::MemoryMapped)
        } else {
            Ok(AnalysisStrategy::InMemory)
        }
    }

    /// Create appropriate file reader based on strategy
    pub fn create_file_reader<P: AsRef<Path>>(
        &self,
        file_path: P,
        strategy: AnalysisStrategy,
    ) -> Result<Box<dyn FileReader>> {
        match strategy {
            AnalysisStrategy::MemoryMapped => {
                let mmap = MemoryMappedFile::new(&file_path)?;
                self.gc.memory_tracker.record_memory_mapped_file();
                Ok(Box::new(mmap))
            }
            AnalysisStrategy::Streaming => {
                let reader = StreamingFileReader::new(&file_path, self.config.chunk_size_bytes)?;
                Ok(Box::new(reader))
            }
            AnalysisStrategy::InMemory => {
                // For in-memory, we'll use streaming but read everything at once
                let reader = StreamingFileReader::new(&file_path, self.config.chunk_size_bytes)?;
                Ok(Box::new(reader))
            }
        }
    }

    /// Get or create a memory pool for a specific type
    pub fn get_memory_pool<T: Default + Clone + Send + Sync + 'static>(
        &mut self,
        name: &str,
    ) -> Arc<MemoryPool<T>> {
        if let Some(pool) = self.memory_pools.get(name) {
            if let Some(typed_pool) = pool.downcast_ref::<MemoryPool<T>>() {
                return Arc::new((*typed_pool).clone());
            }
        }

        let pool = Arc::new(MemoryPool::<T>::new(
            self.config.memory_pool_size / std::mem::size_of::<T>(),
        ));
        self.memory_pools
            .insert(name.to_string(), Box::new(pool.clone()));
        pool
    }

    /// Check memory pressure and provide GC hints
    pub fn check_memory_pressure(&self) -> Result<Option<GCHint>> {
        self.gc.should_collect_garbage()
    }

    /// Get memory statistics
    pub fn memory_stats(&self) -> MemoryStats {
        self.gc.memory_tracker.stats()
    }

    /// Force garbage collection
    pub fn force_gc(&self) -> Result<()> {
        self.gc.force_collection()
    }
}

/// File reading strategy
#[derive(Debug, Clone, Copy)]
pub enum AnalysisStrategy {
    InMemory,
    MemoryMapped,
    Streaming,
}

/// Trait for file readers
pub trait FileReader {
    fn read_all(&mut self) -> Result<Vec<u8>>;
    fn size(&self) -> usize;
}

impl FileReader for MemoryMappedFile {
    fn read_all(&mut self) -> Result<Vec<u8>> {
        Ok(self.as_slice().to_vec())
    }

    fn size(&self) -> usize {
        self.size()
    }
}

impl FileReader for StreamingFileReader {
    fn read_all(&mut self) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(self.file_size());
        while let Some(chunk) = self.read_chunk()? {
            data.extend_from_slice(chunk);
        }
        Ok(data)
    }

    fn size(&self) -> usize {
        self.file_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_memory_mapped_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = b"Hello, memory mapped world!";
        temp_file.write_all(test_data).unwrap();
        temp_file.flush().unwrap();

        let mmap = MemoryMappedFile::new(temp_file.path()).unwrap();
        assert_eq!(mmap.size(), test_data.len());
        assert_eq!(mmap.as_slice(), test_data);
    }

    #[test]
    fn test_streaming_file_reader() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = vec![42u8; 10000]; // 10KB of data
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        let mut reader = StreamingFileReader::new(temp_file.path(), 1024).unwrap();
        let mut read_data = Vec::new();

        while let Some(chunk) = reader.read_chunk().unwrap() {
            read_data.extend_from_slice(chunk);
        }

        assert_eq!(read_data, test_data);
        assert_eq!(reader.total_read(), test_data.len());
    }

    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::<Vec<u8>>::new(10);

        // Get an object from pool
        let obj1 = pool.get();
        assert!(obj1.is_empty());

        // Put object back
        pool.put(vec![1, 2, 3]);

        // Get it again
        let obj2 = pool.get();
        assert_eq!(obj2, vec![1, 2, 3]);

        let stats = pool.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_memory_tracker() {
        let tracker = MemoryTracker::new();

        tracker.record_allocation(1024);
        assert_eq!(tracker.current_usage(), 1024);
        assert_eq!(tracker.peak_usage(), 1024);

        tracker.record_allocation(512);
        assert_eq!(tracker.current_usage(), 1536);
        assert_eq!(tracker.peak_usage(), 1536);

        tracker.record_deallocation(256);
        assert_eq!(tracker.current_usage(), 1280);
        assert_eq!(tracker.peak_usage(), 1536); // Peak should remain
    }

    #[test]
    fn test_analysis_strategy_selection() {
        let config = MemoryConfig {
            streaming_threshold_bytes: 1000,
            enable_memory_mapping: true,
            ..Default::default()
        };

        let manager = AdvancedMemoryManager::new(config);

        // Create a small test file
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"small file").unwrap();
        temp_file.flush().unwrap();

        let strategy = manager.choose_analysis_strategy(temp_file.path()).unwrap();
        match strategy {
            AnalysisStrategy::InMemory | AnalysisStrategy::MemoryMapped => {}
            AnalysisStrategy::Streaming => panic!("Small file should not use streaming"),
        }
    }
}

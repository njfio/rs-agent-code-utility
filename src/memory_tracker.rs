use crate::{Result, Error, FileInfo, AnalysisResult, SyntaxTree};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Comprehensive memory allocation tracking system
#[derive(Debug, Clone)]
pub struct MemoryTracker {
    /// Configuration for memory tracking
    config: MemoryTrackingConfig,
    /// Allocation patterns database
    allocation_patterns: HashMap<String, AllocationPattern>,
    /// Memory usage statistics
    memory_stats: MemoryStatistics,
}

/// Configuration for memory allocation tracking
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryTrackingConfig {
    /// Track heap allocations
    pub track_heap_allocations: bool,
    /// Track stack allocations
    pub track_stack_allocations: bool,
    /// Track memory leaks
    pub detect_memory_leaks: bool,
    /// Track allocation patterns
    pub track_allocation_patterns: bool,
    /// Track memory fragmentation
    pub track_fragmentation: bool,
    /// Minimum allocation size to track (bytes)
    pub min_allocation_size: usize,
    /// Maximum call stack depth to analyze
    pub max_call_stack_depth: usize,
    /// Enable real-time tracking
    pub real_time_tracking: bool,
}

/// Memory allocation tracking results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryTrackingResult {
    /// Total allocations tracked
    pub total_allocations: usize,
    /// Total memory allocated (bytes)
    pub total_memory_allocated: u64,
    /// Peak memory usage (bytes)
    pub peak_memory_usage: u64,
    /// Current memory usage (bytes)
    pub current_memory_usage: u64,
    /// Memory allocation hotspots
    pub allocation_hotspots: Vec<AllocationHotspot>,
    /// Memory leak candidates
    pub leak_candidates: Vec<MemoryLeakCandidate>,
    /// Allocation patterns
    pub allocation_patterns: Vec<AllocationPattern>,
    /// Memory fragmentation analysis
    pub fragmentation_analysis: FragmentationAnalysis,
    /// Memory usage timeline
    pub memory_timeline: Vec<MemorySnapshot>,
    /// Allocation call stacks
    pub call_stacks: Vec<AllocationCallStack>,
}

/// Memory allocation hotspot
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AllocationHotspot {
    /// Unique identifier
    pub id: String,
    /// Location in code
    pub location: AllocationLocation,
    /// Allocation type
    pub allocation_type: AllocationType,
    /// Frequency of allocation
    pub frequency: u64,
    /// Total bytes allocated
    pub total_bytes: u64,
    /// Average allocation size
    pub average_size: f64,
    /// Peak concurrent allocations
    pub peak_concurrent: u64,
    /// Allocation lifetime statistics
    pub lifetime_stats: LifetimeStatistics,
    /// Performance impact
    pub performance_impact: AllocationImpact,
}

/// Location of memory allocation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AllocationLocation {
    /// File path
    pub file: String,
    /// Function name
    pub function: String,
    /// Line number
    pub line: usize,
    /// Column number
    pub column: usize,
    /// Code context
    pub code_context: String,
}

/// Types of memory allocation
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AllocationType {
    /// Heap allocation (malloc, new, Box::new)
    HeapAllocation,
    /// Stack allocation (local variables)
    StackAllocation,
    /// Vector allocation/reallocation
    VectorAllocation,
    /// String allocation
    StringAllocation,
    /// HashMap/BTreeMap allocation
    MapAllocation,
    /// Custom allocator
    CustomAllocation,
    /// Thread-local allocation
    ThreadLocalAllocation,
    /// Global/static allocation
    GlobalAllocation,
}

/// Memory allocation pattern
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AllocationPattern {
    /// Pattern identifier
    pub id: String,
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Allocation sites involved
    pub allocation_sites: Vec<AllocationLocation>,
    /// Pattern frequency
    pub frequency: u64,
    /// Memory usage pattern
    pub usage_pattern: UsagePattern,
    /// Optimization opportunities
    pub optimizations: Vec<String>,
}

/// Memory usage pattern
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UsagePattern {
    /// Allocate once, use many times
    AllocateOnceUseMany,
    /// Frequent allocation/deallocation
    FrequentChurn,
    /// Growing collections
    GrowingCollections,
    /// Temporary allocations
    TemporaryAllocations,
    /// Long-lived allocations
    LongLivedAllocations,
    /// Cyclic allocations
    CyclicAllocations,
}

/// Memory leak candidate
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryLeakCandidate {
    /// Unique identifier
    pub id: String,
    /// Allocation location
    pub allocation_site: AllocationLocation,
    /// Leak type
    pub leak_type: LeakType,
    /// Confidence level
    pub confidence: f64,
    /// Memory size potentially leaked
    pub leaked_bytes: u64,
    /// Time since allocation
    pub age: std::time::Duration,
    /// Call stack at allocation
    pub call_stack: Vec<String>,
    /// Mitigation suggestions
    pub mitigation: Vec<String>,
}

/// Types of memory leaks
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LeakType {
    /// Direct memory leak (not freed)
    DirectLeak,
    /// Indirect leak (reachable from leaked memory)
    IndirectLeak,
    /// Possible leak (still reachable but suspicious)
    PossibleLeak,
    /// Reference cycle
    ReferenceCycle,
    /// Resource leak (file handles, etc.)
    ResourceLeak,
}

/// Memory fragmentation analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FragmentationAnalysis {
    /// Fragmentation percentage
    pub fragmentation_percentage: f64,
    /// Largest free block size
    pub largest_free_block: u64,
    /// Number of free blocks
    pub free_block_count: usize,
    /// Average free block size
    pub average_free_block_size: f64,
    /// Fragmentation hotspots
    pub fragmentation_hotspots: Vec<FragmentationHotspot>,
}

/// Memory fragmentation hotspot
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FragmentationHotspot {
    /// Memory region
    pub region: MemoryRegion,
    /// Fragmentation level
    pub fragmentation_level: f64,
    /// Cause of fragmentation
    pub cause: String,
    /// Suggested fixes
    pub fixes: Vec<String>,
}

/// Memory region
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryRegion {
    /// Start address (for analysis purposes)
    pub start_offset: u64,
    /// Size in bytes
    pub size: u64,
    /// Region type
    pub region_type: String,
}

/// Memory snapshot at a point in time
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemorySnapshot {
    /// Timestamp
    pub timestamp: std::time::SystemTime,
    /// Total memory usage
    pub total_memory: u64,
    /// Heap memory usage
    pub heap_memory: u64,
    /// Stack memory usage
    pub stack_memory: u64,
    /// Number of active allocations
    pub active_allocations: usize,
    /// Memory growth rate (bytes/second)
    pub growth_rate: f64,
}

/// Allocation call stack
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AllocationCallStack {
    /// Allocation identifier
    pub allocation_id: String,
    /// Call stack frames
    pub frames: Vec<StackFrame>,
    /// Total allocations with this stack
    pub allocation_count: u64,
    /// Total bytes allocated with this stack
    pub total_bytes: u64,
}

/// Stack frame information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StackFrame {
    /// Function name
    pub function: String,
    /// File path
    pub file: String,
    /// Line number
    pub line: usize,
    /// Module/namespace
    pub module: String,
}

/// Allocation lifetime statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LifetimeStatistics {
    /// Average lifetime
    pub average_lifetime: std::time::Duration,
    /// Minimum lifetime
    pub min_lifetime: std::time::Duration,
    /// Maximum lifetime
    pub max_lifetime: std::time::Duration,
    /// Standard deviation of lifetime
    pub lifetime_stddev: f64,
    /// Percentage of short-lived allocations
    pub short_lived_percentage: f64,
}

/// Performance impact of allocations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AllocationImpact {
    /// CPU overhead percentage
    pub cpu_overhead: f64,
    /// Memory overhead percentage
    pub memory_overhead: f64,
    /// Cache miss rate increase
    pub cache_miss_increase: f64,
    /// GC pressure (if applicable)
    pub gc_pressure: f64,
    /// Overall performance impact score
    pub overall_impact: f64,
}

/// Memory usage statistics
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryStatistics {
    /// Total allocations tracked
    pub total_allocations: u64,
    /// Total deallocations tracked
    pub total_deallocations: u64,
    /// Current active allocations
    pub active_allocations: u64,
    /// Peak active allocations
    pub peak_active_allocations: u64,
    /// Total bytes allocated
    pub total_bytes_allocated: u64,
    /// Total bytes deallocated
    pub total_bytes_deallocated: u64,
    /// Current bytes in use
    pub current_bytes_in_use: u64,
    /// Peak bytes in use
    pub peak_bytes_in_use: u64,
    /// Allocation rate (allocations/second)
    pub allocation_rate: f64,
    /// Deallocation rate (deallocations/second)
    pub deallocation_rate: f64,
}

impl Default for MemoryTrackingConfig {
    fn default() -> Self {
        Self {
            track_heap_allocations: true,
            track_stack_allocations: false,
            detect_memory_leaks: true,
            track_allocation_patterns: true,
            track_fragmentation: false,
            min_allocation_size: 1,
            max_call_stack_depth: 10,
            real_time_tracking: false,
        }
    }
}

impl MemoryTracker {
    /// Create a new memory tracker with default configuration
    pub fn new() -> Self {
        Self {
            config: MemoryTrackingConfig::default(),
            allocation_patterns: HashMap::new(),
            memory_stats: MemoryStatistics::default(),
        }
    }

    /// Create a new memory tracker with custom configuration
    pub fn with_config(config: MemoryTrackingConfig) -> Self {
        Self {
            config,
            allocation_patterns: HashMap::new(),
            memory_stats: MemoryStatistics::default(),
        }
    }

    /// Analyze memory allocation patterns in a codebase
    pub fn analyze_memory_allocations(&mut self, analysis_result: &AnalysisResult) -> Result<MemoryTrackingResult> {
        let mut allocation_hotspots = Vec::new();
        let mut leak_candidates = Vec::new();
        let mut call_stacks = Vec::new();
        let mut memory_timeline = Vec::new();

        // Analyze each file for memory allocation patterns
        for file in &analysis_result.files {
            if let Ok(content) = std::fs::read_to_string(&file.path) {
                // Detect allocation hotspots
                let hotspots = self.detect_allocation_hotspots(&content, file)?;
                allocation_hotspots.extend(hotspots);

                // Detect potential memory leaks
                let leaks = self.detect_memory_leaks(&content, file)?;
                leak_candidates.extend(leaks);

                // Analyze call stacks
                let stacks = self.analyze_call_stacks(&content, file)?;
                call_stacks.extend(stacks);

                // Update allocation patterns
                self.update_allocation_patterns(&content, file)?;
            }
        }

        // Generate memory timeline
        memory_timeline.push(MemorySnapshot {
            timestamp: std::time::SystemTime::now(),
            total_memory: self.memory_stats.current_bytes_in_use,
            heap_memory: self.memory_stats.current_bytes_in_use,
            stack_memory: 0, // Would need runtime tracking
            active_allocations: self.memory_stats.active_allocations as usize,
            growth_rate: self.memory_stats.allocation_rate - self.memory_stats.deallocation_rate,
        });

        // Analyze fragmentation
        let fragmentation_analysis = self.analyze_fragmentation(&allocation_hotspots)?;

        // Convert patterns to vector
        let allocation_patterns: Vec<AllocationPattern> = self.allocation_patterns.values().cloned().collect();

        Ok(MemoryTrackingResult {
            total_allocations: self.memory_stats.total_allocations as usize,
            total_memory_allocated: self.memory_stats.total_bytes_allocated,
            peak_memory_usage: self.memory_stats.peak_bytes_in_use,
            current_memory_usage: self.memory_stats.current_bytes_in_use,
            allocation_hotspots,
            leak_candidates,
            allocation_patterns,
            fragmentation_analysis,
            memory_timeline,
            call_stacks,
        })
    }

    /// Detect memory allocation hotspots in source code
    fn detect_allocation_hotspots(&self, content: &str, file: &FileInfo) -> Result<Vec<AllocationHotspot>> {
        let mut hotspots = Vec::new();

        // Parse the file using tree-sitter
        let tree = self.parse_file(content, &file.language)?;

        match file.language.to_lowercase().as_str() {
            "rust" => {
                hotspots.extend(self.detect_rust_allocations(&tree, content, file)?);
            },
            "c" | "cpp" | "c++" => {
                hotspots.extend(self.detect_c_cpp_allocations(&tree, content, file)?);
            },
            "python" => {
                hotspots.extend(self.detect_python_allocations(&tree, content, file)?);
            },
            "javascript" | "typescript" => {
                hotspots.extend(self.detect_js_allocations(&tree, content, file)?);
            },
            "go" => {
                hotspots.extend(self.detect_go_allocations(&tree, content, file)?);
            },
            _ => {
                // Generic allocation detection
                hotspots.extend(self.detect_generic_allocations(content, file)?);
            }
        }

        Ok(hotspots)
    }

    /// Parse file content using appropriate tree-sitter parser
    fn parse_file(&self, content: &str, language: &str) -> Result<SyntaxTree> {
        use crate::{Language, Parser};

        let lang = match language.to_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "c" => Language::C,
            "cpp" | "c++" => Language::Cpp,
            "go" => Language::Go,
            _ => return Err(Error::not_supported_error(
                format!("Language: {}", language),
                "Memory tracking not implemented for this language"
            )),
        };

        let parser = Parser::new(lang)?;
        parser.parse(content, None)
    }

    /// Detect Rust-specific memory allocations
    fn detect_rust_allocations(&self, tree: &SyntaxTree, content: &str, file: &FileInfo) -> Result<Vec<AllocationHotspot>> {
        let mut hotspots = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Look for common Rust allocation patterns
        let allocation_patterns = [
            ("Vec::new", AllocationType::VectorAllocation),
            ("Vec::with_capacity", AllocationType::VectorAllocation),
            ("String::new", AllocationType::StringAllocation),
            ("String::with_capacity", AllocationType::StringAllocation),
            ("Box::new", AllocationType::HeapAllocation),
            ("HashMap::new", AllocationType::MapAllocation),
            ("BTreeMap::new", AllocationType::MapAllocation),
            ("vec!", AllocationType::VectorAllocation),
        ];

        for (pattern, alloc_type) in &allocation_patterns {
            let call_expressions = tree.find_nodes_by_kind("call_expression");
            for call in call_expressions {
                if let Some(function) = call.child_by_field_name("function") {
                    let function_text = function.text().unwrap_or("");
                    if function_text.contains(pattern) {
                        let start_point = call.start_position();
                        let line_num = start_point.row;

                        if line_num < lines.len() {
                            let code_context = lines[line_num].trim().to_string();
                            let in_loop = self.is_allocation_in_loop_simple(start_point.row, &lines);

                            hotspots.push(AllocationHotspot {
                                id: format!("RUST_ALLOC_{}_{}", file.path.display(), line_num),
                                location: AllocationLocation {
                                    file: file.path.display().to_string(),
                                    function: self.find_function_at_line(line_num, &lines).unwrap_or_default(),
                                    line: line_num + 1,
                                    column: start_point.column + 1,
                                    code_context,
                                },
                                allocation_type: alloc_type.clone(),
                                frequency: if in_loop { 1000 } else { 1 }, // Estimate based on loop context
                                total_bytes: self.estimate_allocation_size(pattern),
                                average_size: self.estimate_allocation_size(pattern) as f64,
                                peak_concurrent: if in_loop { 100 } else { 1 },
                                lifetime_stats: LifetimeStatistics {
                                    average_lifetime: std::time::Duration::from_millis(100),
                                    min_lifetime: std::time::Duration::from_millis(1),
                                    max_lifetime: std::time::Duration::from_secs(1),
                                    lifetime_stddev: 50.0,
                                    short_lived_percentage: if in_loop { 80.0 } else { 20.0 },
                                },
                                performance_impact: AllocationImpact {
                                    cpu_overhead: if in_loop { 15.0 } else { 2.0 },
                                    memory_overhead: 10.0,
                                    cache_miss_increase: if in_loop { 25.0 } else { 5.0 },
                                    gc_pressure: 0.0, // Rust doesn't have GC
                                    overall_impact: if in_loop { 20.0 } else { 5.0 },
                                },
                            });
                        }
                    }
                }
            }
        }

        Ok(hotspots)
    }

    /// Detect C/C++ memory allocations
    fn detect_c_cpp_allocations(&self, tree: &SyntaxTree, content: &str, file: &FileInfo) -> Result<Vec<AllocationHotspot>> {
        let mut hotspots = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // C/C++ allocation patterns
        let allocation_patterns = [
            ("malloc", AllocationType::HeapAllocation),
            ("calloc", AllocationType::HeapAllocation),
            ("realloc", AllocationType::HeapAllocation),
            ("new", AllocationType::HeapAllocation),
            ("new[]", AllocationType::HeapAllocation),
        ];

        for (pattern, alloc_type) in &allocation_patterns {
            let call_expressions = tree.find_nodes_by_kind("call_expression");
            for call in call_expressions {
                if let Some(function) = call.child_by_field_name("function") {
                    let function_text = function.text().unwrap_or("");
                    if function_text == *pattern {
                        let start_point = call.start_position();
                        let line_num = start_point.row;

                        if line_num < lines.len() {
                            let code_context = lines[line_num].trim().to_string();
                            let in_loop = self.is_allocation_in_loop_simple(start_point.row, &lines);

                            hotspots.push(AllocationHotspot {
                                id: format!("CPP_ALLOC_{}_{}", file.path.display(), line_num),
                                location: AllocationLocation {
                                    file: file.path.display().to_string(),
                                    function: self.find_function_at_line(line_num, &lines).unwrap_or_default(),
                                    line: line_num + 1,
                                    column: start_point.column + 1,
                                    code_context,
                                },
                                allocation_type: alloc_type.clone(),
                                frequency: if in_loop { 1000 } else { 1 },
                                total_bytes: self.estimate_allocation_size(pattern),
                                average_size: self.estimate_allocation_size(pattern) as f64,
                                peak_concurrent: if in_loop { 100 } else { 1 },
                                lifetime_stats: LifetimeStatistics {
                                    average_lifetime: std::time::Duration::from_millis(500),
                                    min_lifetime: std::time::Duration::from_millis(1),
                                    max_lifetime: std::time::Duration::from_secs(10),
                                    lifetime_stddev: 200.0,
                                    short_lived_percentage: if in_loop { 60.0 } else { 30.0 },
                                },
                                performance_impact: AllocationImpact {
                                    cpu_overhead: if in_loop { 20.0 } else { 3.0 },
                                    memory_overhead: 15.0,
                                    cache_miss_increase: if in_loop { 30.0 } else { 8.0 },
                                    gc_pressure: 0.0,
                                    overall_impact: if in_loop { 25.0 } else { 8.0 },
                                },
                            });
                        }
                    }
                }
            }
        }

        Ok(hotspots)
    }

    /// Detect Python memory allocations
    fn detect_python_allocations(&self, _tree: &SyntaxTree, content: &str, file: &FileInfo) -> Result<Vec<AllocationHotspot>> {
        let mut hotspots = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Python allocation patterns
        let allocation_patterns = [
            ("list(", AllocationType::VectorAllocation),
            ("dict(", AllocationType::MapAllocation),
            ("set(", AllocationType::MapAllocation),
            ("[]", AllocationType::VectorAllocation),
            ("{}", AllocationType::MapAllocation),
        ];

        for (pattern, alloc_type) in &allocation_patterns {
            for (line_num, line) in lines.iter().enumerate() {
                if line.contains(pattern) {
                    let in_loop = self.is_line_in_loop(line_num, &lines);

                    hotspots.push(AllocationHotspot {
                        id: format!("PYTHON_ALLOC_{}_{}", file.path.display(), line_num),
                        location: AllocationLocation {
                            file: file.path.display().to_string(),
                            function: self.find_function_at_line(line_num, &lines).unwrap_or_default(),
                            line: line_num + 1,
                            column: line.find(pattern).unwrap_or(0) + 1,
                            code_context: line.trim().to_string(),
                        },
                        allocation_type: alloc_type.clone(),
                        frequency: if in_loop { 500 } else { 1 },
                        total_bytes: self.estimate_allocation_size(pattern),
                        average_size: self.estimate_allocation_size(pattern) as f64,
                        peak_concurrent: if in_loop { 50 } else { 1 },
                        lifetime_stats: LifetimeStatistics {
                            average_lifetime: std::time::Duration::from_millis(200),
                            min_lifetime: std::time::Duration::from_millis(1),
                            max_lifetime: std::time::Duration::from_secs(5),
                            lifetime_stddev: 100.0,
                            short_lived_percentage: if in_loop { 70.0 } else { 40.0 },
                        },
                        performance_impact: AllocationImpact {
                            cpu_overhead: if in_loop { 10.0 } else { 2.0 },
                            memory_overhead: 20.0,
                            cache_miss_increase: if in_loop { 15.0 } else { 5.0 },
                            gc_pressure: if in_loop { 30.0 } else { 10.0 },
                            overall_impact: if in_loop { 18.0 } else { 7.0 },
                        },
                    });
                }
            }
        }

        Ok(hotspots)
    }

    /// Detect JavaScript/TypeScript memory allocations
    fn detect_js_allocations(&self, _tree: &SyntaxTree, content: &str, file: &FileInfo) -> Result<Vec<AllocationHotspot>> {
        let mut hotspots = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // JavaScript allocation patterns
        let allocation_patterns = [
            ("new Array", AllocationType::VectorAllocation),
            ("new Object", AllocationType::MapAllocation),
            ("new Map", AllocationType::MapAllocation),
            ("new Set", AllocationType::MapAllocation),
            ("[]", AllocationType::VectorAllocation),
            ("{}", AllocationType::MapAllocation),
        ];

        for (pattern, alloc_type) in &allocation_patterns {
            for (line_num, line) in lines.iter().enumerate() {
                if line.contains(pattern) {
                    let in_loop = self.is_line_in_loop(line_num, &lines);

                    hotspots.push(AllocationHotspot {
                        id: format!("JS_ALLOC_{}_{}", file.path.display(), line_num),
                        location: AllocationLocation {
                            file: file.path.display().to_string(),
                            function: self.find_function_at_line(line_num, &lines).unwrap_or_default(),
                            line: line_num + 1,
                            column: line.find(pattern).unwrap_or(0) + 1,
                            code_context: line.trim().to_string(),
                        },
                        allocation_type: alloc_type.clone(),
                        frequency: if in_loop { 800 } else { 1 },
                        total_bytes: self.estimate_allocation_size(pattern),
                        average_size: self.estimate_allocation_size(pattern) as f64,
                        peak_concurrent: if in_loop { 80 } else { 1 },
                        lifetime_stats: LifetimeStatistics {
                            average_lifetime: std::time::Duration::from_millis(150),
                            min_lifetime: std::time::Duration::from_millis(1),
                            max_lifetime: std::time::Duration::from_secs(3),
                            lifetime_stddev: 75.0,
                            short_lived_percentage: if in_loop { 85.0 } else { 50.0 },
                        },
                        performance_impact: AllocationImpact {
                            cpu_overhead: if in_loop { 12.0 } else { 3.0 },
                            memory_overhead: 25.0,
                            cache_miss_increase: if in_loop { 20.0 } else { 6.0 },
                            gc_pressure: if in_loop { 40.0 } else { 15.0 },
                            overall_impact: if in_loop { 22.0 } else { 9.0 },
                        },
                    });
                }
            }
        }

        Ok(hotspots)
    }

    /// Detect Go memory allocations
    fn detect_go_allocations(&self, _tree: &SyntaxTree, content: &str, file: &FileInfo) -> Result<Vec<AllocationHotspot>> {
        let mut hotspots = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Go allocation patterns
        let allocation_patterns = [
            ("make(", AllocationType::VectorAllocation),
            ("new(", AllocationType::HeapAllocation),
            ("&", AllocationType::HeapAllocation), // Address operator can cause heap allocation
        ];

        for (pattern, alloc_type) in &allocation_patterns {
            for (line_num, line) in lines.iter().enumerate() {
                if line.contains(pattern) {
                    let in_loop = self.is_line_in_loop(line_num, &lines);

                    hotspots.push(AllocationHotspot {
                        id: format!("GO_ALLOC_{}_{}", file.path.display(), line_num),
                        location: AllocationLocation {
                            file: file.path.display().to_string(),
                            function: self.find_function_at_line(line_num, &lines).unwrap_or_default(),
                            line: line_num + 1,
                            column: line.find(pattern).unwrap_or(0) + 1,
                            code_context: line.trim().to_string(),
                        },
                        allocation_type: alloc_type.clone(),
                        frequency: if in_loop { 600 } else { 1 },
                        total_bytes: self.estimate_allocation_size(pattern),
                        average_size: self.estimate_allocation_size(pattern) as f64,
                        peak_concurrent: if in_loop { 60 } else { 1 },
                        lifetime_stats: LifetimeStatistics {
                            average_lifetime: std::time::Duration::from_millis(300),
                            min_lifetime: std::time::Duration::from_millis(1),
                            max_lifetime: std::time::Duration::from_secs(8),
                            lifetime_stddev: 150.0,
                            short_lived_percentage: if in_loop { 75.0 } else { 35.0 },
                        },
                        performance_impact: AllocationImpact {
                            cpu_overhead: if in_loop { 8.0 } else { 2.0 },
                            memory_overhead: 12.0,
                            cache_miss_increase: if in_loop { 18.0 } else { 4.0 },
                            gc_pressure: if in_loop { 25.0 } else { 8.0 },
                            overall_impact: if in_loop { 15.0 } else { 5.0 },
                        },
                    });
                }
            }
        }

        Ok(hotspots)
    }

    /// Generic allocation detection for unsupported languages
    fn detect_generic_allocations(&self, content: &str, file: &FileInfo) -> Result<Vec<AllocationHotspot>> {
        let mut hotspots = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Generic allocation keywords
        let allocation_keywords = ["alloc", "malloc", "new", "create", "make"];

        for (line_num, line) in lines.iter().enumerate() {
            for keyword in &allocation_keywords {
                if line.to_lowercase().contains(keyword) {
                    let in_loop = self.is_line_in_loop(line_num, &lines);

                    hotspots.push(AllocationHotspot {
                        id: format!("GENERIC_ALLOC_{}_{}", file.path.display(), line_num),
                        location: AllocationLocation {
                            file: file.path.display().to_string(),
                            function: self.find_function_at_line(line_num, &lines).unwrap_or_default(),
                            line: line_num + 1,
                            column: line.find(keyword).unwrap_or(0) + 1,
                            code_context: line.trim().to_string(),
                        },
                        allocation_type: AllocationType::HeapAllocation,
                        frequency: if in_loop { 100 } else { 1 },
                        total_bytes: 1024, // Generic estimate
                        average_size: 1024.0,
                        peak_concurrent: if in_loop { 10 } else { 1 },
                        lifetime_stats: LifetimeStatistics {
                            average_lifetime: std::time::Duration::from_millis(1000),
                            min_lifetime: std::time::Duration::from_millis(1),
                            max_lifetime: std::time::Duration::from_secs(60),
                            lifetime_stddev: 500.0,
                            short_lived_percentage: 50.0,
                        },
                        performance_impact: AllocationImpact {
                            cpu_overhead: if in_loop { 5.0 } else { 1.0 },
                            memory_overhead: 10.0,
                            cache_miss_increase: if in_loop { 10.0 } else { 2.0 },
                            gc_pressure: 5.0,
                            overall_impact: if in_loop { 7.0 } else { 3.0 },
                        },
                    });
                    break; // Only one hotspot per line
                }
            }
        }

        Ok(hotspots)
    }

    /// Detect potential memory leaks
    fn detect_memory_leaks(&self, content: &str, file: &FileInfo) -> Result<Vec<MemoryLeakCandidate>> {
        let mut leak_candidates = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        match file.language.to_lowercase().as_str() {
            "rust" => {
                leak_candidates.extend(self.detect_rust_memory_leaks(&lines, file)?);
            },
            "c" | "cpp" | "c++" => {
                leak_candidates.extend(self.detect_c_cpp_memory_leaks(&lines, file)?);
            },
            "python" => {
                leak_candidates.extend(self.detect_python_memory_leaks(&lines, file)?);
            },
            "javascript" | "typescript" => {
                leak_candidates.extend(self.detect_js_memory_leaks(&lines, file)?);
            },
            _ => {
                // Generic leak detection
                leak_candidates.extend(self.detect_generic_memory_leaks(&lines, file)?);
            }
        }

        Ok(leak_candidates)
    }

    /// Detect Rust-specific memory leaks
    fn detect_rust_memory_leaks(&self, lines: &[&str], file: &FileInfo) -> Result<Vec<MemoryLeakCandidate>> {
        let mut candidates = Vec::new();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Reference cycles with Rc<RefCell<T>>
            if trimmed.contains("Rc::new") && trimmed.contains("RefCell") {
                candidates.push(MemoryLeakCandidate {
                    id: format!("RUST_LEAK_RC_{}_{}", file.path.display(), line_num),
                    allocation_site: AllocationLocation {
                        file: file.path.display().to_string(),
                        function: self.find_function_at_line(line_num, lines).unwrap_or_default(),
                        line: line_num + 1,
                        column: trimmed.find("Rc::new").unwrap_or(0) + 1,
                        code_context: trimmed.to_string(),
                    },
                    leak_type: LeakType::ReferenceCycle,
                    confidence: 0.7,
                    leaked_bytes: 1024, // Estimate
                    age: std::time::Duration::from_secs(0), // Would be tracked at runtime
                    call_stack: vec![format!("{}:{}", file.path.display(), line_num + 1)],
                    mitigation: vec![
                        "Use Weak references to break cycles".to_string(),
                        "Consider alternative data structures".to_string(),
                    ],
                });
            }

            // Explicit memory leaks
            if trimmed.contains("Box::leak") || trimmed.contains("mem::forget") {
                candidates.push(MemoryLeakCandidate {
                    id: format!("RUST_LEAK_EXPLICIT_{}_{}", file.path.display(), line_num),
                    allocation_site: AllocationLocation {
                        file: file.path.display().to_string(),
                        function: self.find_function_at_line(line_num, lines).unwrap_or_default(),
                        line: line_num + 1,
                        column: 0,
                        code_context: trimmed.to_string(),
                    },
                    leak_type: LeakType::DirectLeak,
                    confidence: 0.95,
                    leaked_bytes: 2048, // Estimate
                    age: std::time::Duration::from_secs(0),
                    call_stack: vec![format!("{}:{}", file.path.display(), line_num + 1)],
                    mitigation: vec![
                        "Ensure this is intentional and necessary".to_string(),
                        "Document the reason for the leak".to_string(),
                    ],
                });
            }
        }

        Ok(candidates)
    }

    /// Detect C/C++ memory leaks
    fn detect_c_cpp_memory_leaks(&self, lines: &[&str], file: &FileInfo) -> Result<Vec<MemoryLeakCandidate>> {
        let mut candidates = Vec::new();
        let mut allocations = HashSet::new();
        let mut deallocations = HashSet::new();

        // Track allocations and deallocations
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            if trimmed.contains("malloc") || trimmed.contains("calloc") || trimmed.contains("new ") {
                allocations.insert(line_num);
            }

            if trimmed.contains("free") || trimmed.contains("delete ") {
                deallocations.insert(line_num);
            }
        }

        // Simple heuristic: if there are more allocations than deallocations, potential leak
        if allocations.len() > deallocations.len() {
            for &alloc_line in &allocations {
                if alloc_line < lines.len() {
                    candidates.push(MemoryLeakCandidate {
                        id: format!("CPP_LEAK_{}_{}", file.path.display(), alloc_line),
                        allocation_site: AllocationLocation {
                            file: file.path.display().to_string(),
                            function: self.find_function_at_line(alloc_line, lines).unwrap_or_default(),
                            line: alloc_line + 1,
                            column: 0,
                            code_context: lines[alloc_line].trim().to_string(),
                        },
                        leak_type: LeakType::PossibleLeak,
                        confidence: 0.5, // Low confidence without flow analysis
                        leaked_bytes: 4096, // Estimate
                        age: std::time::Duration::from_secs(0),
                        call_stack: vec![format!("{}:{}", file.path.display(), alloc_line + 1)],
                        mitigation: vec![
                            "Ensure corresponding free/delete is called".to_string(),
                            "Use RAII or smart pointers".to_string(),
                        ],
                    });
                }
            }
        }

        Ok(candidates)
    }

    /// Detect Python memory leaks
    fn detect_python_memory_leaks(&self, lines: &[&str], file: &FileInfo) -> Result<Vec<MemoryLeakCandidate>> {
        let mut candidates = Vec::new();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Circular references
            if trimmed.contains("self.") && (trimmed.contains("parent") || trimmed.contains("child")) {
                candidates.push(MemoryLeakCandidate {
                    id: format!("PYTHON_LEAK_CIRCULAR_{}_{}", file.path.display(), line_num),
                    allocation_site: AllocationLocation {
                        file: file.path.display().to_string(),
                        function: self.find_function_at_line(line_num, lines).unwrap_or_default(),
                        line: line_num + 1,
                        column: 0,
                        code_context: trimmed.to_string(),
                    },
                    leak_type: LeakType::ReferenceCycle,
                    confidence: 0.6,
                    leaked_bytes: 512, // Estimate
                    age: std::time::Duration::from_secs(0),
                    call_stack: vec![format!("{}:{}", file.path.display(), line_num + 1)],
                    mitigation: vec![
                        "Use weak references for parent-child relationships".to_string(),
                        "Implement proper cleanup methods".to_string(),
                    ],
                });
            }
        }

        Ok(candidates)
    }

    /// Detect JavaScript memory leaks
    fn detect_js_memory_leaks(&self, lines: &[&str], file: &FileInfo) -> Result<Vec<MemoryLeakCandidate>> {
        let mut candidates = Vec::new();

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // Event listeners without cleanup
            if trimmed.contains("addEventListener") && !self.has_corresponding_remove_listener(line_num, lines) {
                candidates.push(MemoryLeakCandidate {
                    id: format!("JS_LEAK_LISTENER_{}_{}", file.path.display(), line_num),
                    allocation_site: AllocationLocation {
                        file: file.path.display().to_string(),
                        function: self.find_function_at_line(line_num, lines).unwrap_or_default(),
                        line: line_num + 1,
                        column: 0,
                        code_context: trimmed.to_string(),
                    },
                    leak_type: LeakType::ResourceLeak,
                    confidence: 0.8,
                    leaked_bytes: 256, // Estimate for event listener
                    age: std::time::Duration::from_secs(0),
                    call_stack: vec![format!("{}:{}", file.path.display(), line_num + 1)],
                    mitigation: vec![
                        "Add corresponding removeEventListener".to_string(),
                        "Use AbortController for cleanup".to_string(),
                    ],
                });
            }

            // Closures capturing large objects
            if trimmed.contains("function") && trimmed.contains("=>") && trimmed.len() > 100 {
                candidates.push(MemoryLeakCandidate {
                    id: format!("JS_LEAK_CLOSURE_{}_{}", file.path.display(), line_num),
                    allocation_site: AllocationLocation {
                        file: file.path.display().to_string(),
                        function: self.find_function_at_line(line_num, lines).unwrap_or_default(),
                        line: line_num + 1,
                        column: 0,
                        code_context: trimmed.to_string(),
                    },
                    leak_type: LeakType::PossibleLeak,
                    confidence: 0.4,
                    leaked_bytes: 1024, // Estimate
                    age: std::time::Duration::from_secs(0),
                    call_stack: vec![format!("{}:{}", file.path.display(), line_num + 1)],
                    mitigation: vec![
                        "Minimize closure scope".to_string(),
                        "Avoid capturing large objects".to_string(),
                    ],
                });
            }
        }

        Ok(candidates)
    }

    /// Generic memory leak detection
    fn detect_generic_memory_leaks(&self, lines: &[&str], file: &FileInfo) -> Result<Vec<MemoryLeakCandidate>> {
        let mut candidates = Vec::new();

        // Simple heuristic: look for allocation without corresponding cleanup
        let mut allocation_lines = Vec::new();
        let mut cleanup_lines = Vec::new();

        for (line_num, line) in lines.iter().enumerate() {
            let lower = line.to_lowercase();

            if lower.contains("alloc") || lower.contains("new") || lower.contains("create") {
                allocation_lines.push(line_num);
            }

            if lower.contains("free") || lower.contains("delete") || lower.contains("close") || lower.contains("cleanup") {
                cleanup_lines.push(line_num);
            }
        }

        // If significantly more allocations than cleanups, flag as potential leaks
        if allocation_lines.len() > cleanup_lines.len() + 2 {
            for &alloc_line in &allocation_lines {
                if alloc_line < lines.len() {
                    candidates.push(MemoryLeakCandidate {
                        id: format!("GENERIC_LEAK_{}_{}", file.path.display(), alloc_line),
                        allocation_site: AllocationLocation {
                            file: file.path.display().to_string(),
                            function: self.find_function_at_line(alloc_line, lines).unwrap_or_default(),
                            line: alloc_line + 1,
                            column: 0,
                            code_context: lines[alloc_line].trim().to_string(),
                        },
                        leak_type: LeakType::PossibleLeak,
                        confidence: 0.3, // Low confidence for generic detection
                        leaked_bytes: 1024, // Generic estimate
                        age: std::time::Duration::from_secs(0),
                        call_stack: vec![format!("{}:{}", file.path.display(), alloc_line + 1)],
                        mitigation: vec![
                            "Ensure proper resource cleanup".to_string(),
                            "Use RAII patterns where possible".to_string(),
                        ],
                    });
                }
            }
        }

        Ok(candidates)
    }

    /// Analyze call stacks for allocation patterns
    fn analyze_call_stacks(&self, content: &str, file: &FileInfo) -> Result<Vec<AllocationCallStack>> {
        let mut call_stacks = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Simple call stack analysis - find function calls leading to allocations
        for (line_num, line) in lines.iter().enumerate() {
            if self.contains_allocation_pattern(line) {
                let mut frames = Vec::new();

                // Look backwards for function calls
                let start = line_num.saturating_sub(self.config.max_call_stack_depth);
                for i in start..=line_num {
                    if i < lines.len() {
                        if let Some(function_name) = self.extract_function_call(lines[i]) {
                            frames.push(StackFrame {
                                function: function_name,
                                file: file.path.display().to_string(),
                                line: i + 1,
                                module: file.path.file_stem()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("unknown")
                                    .to_string(),
                            });
                        }
                    }
                }

                if !frames.is_empty() {
                    call_stacks.push(AllocationCallStack {
                        allocation_id: format!("STACK_{}_{}", file.path.display(), line_num),
                        frames,
                        allocation_count: 1, // Would be tracked at runtime
                        total_bytes: self.estimate_allocation_size(line),
                    });
                }
            }
        }

        Ok(call_stacks)
    }

    /// Update allocation patterns database
    fn update_allocation_patterns(&mut self, content: &str, _file: &FileInfo) -> Result<()> {
        let lines: Vec<&str> = content.lines().collect();

        // Detect common allocation patterns
        let mut pattern_counts = HashMap::new();

        for line in &lines {
            if self.contains_allocation_pattern(line) {
                let pattern_key = self.classify_allocation_pattern(line);
                *pattern_counts.entry(pattern_key.clone()).or_insert(0) += 1;
            }
        }

        // Update patterns database
        for (pattern_key, count) in pattern_counts {
            let pattern_id = format!("PATTERN_{}", pattern_key);

            if let Some(existing_pattern) = self.allocation_patterns.get_mut(&pattern_id) {
                existing_pattern.frequency += count;
            } else {
                let pattern = AllocationPattern {
                    id: pattern_id.clone(),
                    name: pattern_key.clone(),
                    description: format!("Allocation pattern: {}", pattern_key),
                    allocation_sites: Vec::new(), // Would be populated with detailed analysis
                    frequency: count,
                    usage_pattern: self.infer_usage_pattern(&pattern_key),
                    optimizations: self.suggest_optimizations(&pattern_key),
                };
                self.allocation_patterns.insert(pattern_id, pattern);
            }
        }

        Ok(())
    }

    /// Analyze memory fragmentation
    fn analyze_fragmentation(&self, hotspots: &[AllocationHotspot]) -> Result<FragmentationAnalysis> {
        // Simple fragmentation analysis based on allocation patterns
        let total_allocations = hotspots.len();
        let small_allocations = hotspots.iter()
            .filter(|h| h.average_size < 1024.0)
            .count();

        let fragmentation_percentage = if total_allocations > 0 {
            (small_allocations as f64 / total_allocations as f64) * 100.0
        } else {
            0.0
        };

        let fragmentation_hotspots = hotspots.iter()
            .filter(|h| h.frequency > 100 && h.average_size < 512.0)
            .map(|h| FragmentationHotspot {
                region: MemoryRegion {
                    start_offset: 0, // Would need runtime tracking
                    size: h.total_bytes,
                    region_type: format!("{:?}", h.allocation_type),
                },
                fragmentation_level: fragmentation_percentage,
                cause: "Frequent small allocations".to_string(),
                fixes: vec![
                    "Use memory pools".to_string(),
                    "Batch allocations".to_string(),
                    "Pre-allocate with capacity".to_string(),
                ],
            })
            .collect();

        Ok(FragmentationAnalysis {
            fragmentation_percentage,
            largest_free_block: 0, // Would need runtime tracking
            free_block_count: 0,    // Would need runtime tracking
            average_free_block_size: 0.0, // Would need runtime tracking
            fragmentation_hotspots,
        })
    }

    // Helper methods

    /// Check if allocation is inside a loop (simple heuristic version)
    fn is_allocation_in_loop_simple(&self, line_num: usize, lines: &[&str]) -> bool {
        // Look backwards for loop keywords
        let start = line_num.saturating_sub(10);
        for i in start..line_num {
            if i < lines.len() {
                let line = lines[i].trim().to_lowercase();
                if line.starts_with("for ") || line.starts_with("while ") ||
                   line.contains(" for ") || line.contains(" while ") ||
                   line.starts_with("loop ") {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a line is inside a loop (simple heuristic)
    fn is_line_in_loop(&self, line_num: usize, lines: &[&str]) -> bool {
        // Look backwards for loop keywords
        let start = line_num.saturating_sub(10);
        for i in start..line_num {
            if i < lines.len() {
                let line = lines[i].trim().to_lowercase();
                if line.starts_with("for ") || line.starts_with("while ") ||
                   line.contains(" for ") || line.contains(" while ") {
                    return true;
                }
            }
        }
        false
    }

    /// Find the containing function for a node (simplified version)
    #[allow(dead_code)]
    fn find_containing_function_simple(&self, line_num: usize, lines: &[&str]) -> Option<String> {
        // Look backwards for function definition
        let start = line_num.saturating_sub(20);
        for i in start..=line_num {
            if i < lines.len() {
                let line = lines[i].trim();
                if let Some(func_name) = self.extract_function_name(line) {
                    return Some(func_name);
                }
            }
        }
        None
    }

    /// Find function at a specific line
    fn find_function_at_line(&self, line_num: usize, lines: &[&str]) -> Option<String> {
        // Look backwards for function definition
        let start = line_num.saturating_sub(20);
        for i in start..=line_num {
            if i < lines.len() {
                let line = lines[i].trim();
                if let Some(func_name) = self.extract_function_name(line) {
                    return Some(func_name);
                }
            }
        }
        None
    }

    /// Extract function name from a line
    fn extract_function_name(&self, line: &str) -> Option<String> {
        // Simple regex-like extraction for common patterns
        if line.contains("fn ") {
            // Rust function
            if let Some(start) = line.find("fn ") {
                let after_fn = &line[start + 3..];
                if let Some(end) = after_fn.find('(') {
                    return Some(after_fn[..end].trim().to_string());
                }
            }
        } else if line.contains("def ") {
            // Python function
            if let Some(start) = line.find("def ") {
                let after_def = &line[start + 4..];
                if let Some(end) = after_def.find('(') {
                    return Some(after_def[..end].trim().to_string());
                }
            }
        } else if line.contains("function ") {
            // JavaScript function
            if let Some(start) = line.find("function ") {
                let after_func = &line[start + 9..];
                if let Some(end) = after_func.find('(') {
                    return Some(after_func[..end].trim().to_string());
                }
            }
        }
        None
    }

    /// Estimate allocation size based on pattern
    fn estimate_allocation_size(&self, pattern: &str) -> u64 {
        match pattern {
            p if p.contains("Vec") => 1024,      // Vector with some capacity
            p if p.contains("String") => 256,    // String with some content
            p if p.contains("HashMap") => 2048,  // HashMap with some entries
            p if p.contains("Box") => 64,        // Single boxed value
            p if p.contains("malloc") => 4096,   // Generic malloc
            p if p.contains("new") => 512,       // Generic new
            _ => 1024,                           // Default estimate
        }
    }

    /// Check if line contains allocation pattern
    fn contains_allocation_pattern(&self, line: &str) -> bool {
        let lower = line.to_lowercase();
        lower.contains("new") || lower.contains("alloc") || lower.contains("malloc") ||
        lower.contains("vec!") || lower.contains("::new") || lower.contains("make(")
    }

    /// Extract function call from line
    fn extract_function_call(&self, line: &str) -> Option<String> {
        // Look for function call patterns
        if let Some(pos) = line.find('(') {
            let before_paren = &line[..pos];
            if let Some(last_word_start) = before_paren.rfind(|c: char| c.is_whitespace() || c == '.') {
                let func_name = before_paren[last_word_start + 1..].trim();
                if !func_name.is_empty() && func_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    return Some(func_name.to_string());
                }
            } else if !before_paren.trim().is_empty() {
                return Some(before_paren.trim().to_string());
            }
        }
        None
    }

    /// Classify allocation pattern
    fn classify_allocation_pattern(&self, line: &str) -> String {
        let lower = line.to_lowercase();
        if lower.contains("vec") {
            "vector_allocation".to_string()
        } else if lower.contains("string") {
            "string_allocation".to_string()
        } else if lower.contains("hashmap") || lower.contains("btreemap") {
            "map_allocation".to_string()
        } else if lower.contains("box") {
            "box_allocation".to_string()
        } else if lower.contains("malloc") || lower.contains("calloc") {
            "c_allocation".to_string()
        } else if lower.contains("new") {
            "generic_allocation".to_string()
        } else {
            "unknown_allocation".to_string()
        }
    }

    /// Infer usage pattern from allocation type
    fn infer_usage_pattern(&self, pattern_key: &str) -> UsagePattern {
        match pattern_key {
            "vector_allocation" => UsagePattern::GrowingCollections,
            "string_allocation" => UsagePattern::TemporaryAllocations,
            "map_allocation" => UsagePattern::LongLivedAllocations,
            "box_allocation" => UsagePattern::AllocateOnceUseMany,
            _ => UsagePattern::FrequentChurn,
        }
    }

    /// Suggest optimizations for allocation pattern
    fn suggest_optimizations(&self, pattern_key: &str) -> Vec<String> {
        match pattern_key {
            "vector_allocation" => vec![
                "Use Vec::with_capacity() when size is known".to_string(),
                "Consider using SmallVec for small collections".to_string(),
                "Reuse vectors instead of creating new ones".to_string(),
            ],
            "string_allocation" => vec![
                "Use String::with_capacity() for large strings".to_string(),
                "Consider using &str when possible".to_string(),
                "Use string interning for repeated strings".to_string(),
            ],
            "map_allocation" => vec![
                "Pre-allocate with HashMap::with_capacity()".to_string(),
                "Consider using FxHashMap for better performance".to_string(),
                "Use BTreeMap only when ordering is needed".to_string(),
            ],
            "box_allocation" => vec![
                "Consider stack allocation if size is small".to_string(),
                "Use Rc/Arc for shared ownership".to_string(),
                "Pool allocations for frequent use".to_string(),
            ],
            _ => vec![
                "Profile allocation patterns".to_string(),
                "Consider object pooling".to_string(),
                "Use arena allocators for bulk allocations".to_string(),
            ],
        }
    }

    /// Check if there's a corresponding removeEventListener
    fn has_corresponding_remove_listener(&self, line_num: usize, lines: &[&str]) -> bool {
        // Look ahead for removeEventListener
        let end = (line_num + 20).min(lines.len());
        for i in line_num + 1..end {
            if lines[i].contains("removeEventListener") {
                return true;
            }
        }
        false
    }

    /// Get memory tracking statistics
    pub fn get_statistics(&self) -> &MemoryStatistics {
        &self.memory_stats
    }

    /// Reset tracking statistics
    pub fn reset_statistics(&mut self) {
        self.memory_stats = MemoryStatistics::default();
        self.allocation_patterns.clear();
    }

    /// Update configuration
    pub fn update_config(&mut self, config: MemoryTrackingConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &MemoryTrackingConfig {
        &self.config
    }
}

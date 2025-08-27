//! Intent mapping system stub implementation
//!
//! This module provides a basic implementation of the intent mapping system
//! when the ML feature is disabled. It provides the same API as the full
//! ML-powered version but with simplified, rule-based implementations.

use crate::{Result, Error};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Intent mapping system without ML dependencies
///
/// This implementation provides basic intent mapping functionality using
/// rule-based approaches instead of machine learning models.
#[derive(Debug, Clone)]
pub struct IntentMappingSystem {
    requirements: HashMap<String, Requirement>,
    implementations: HashMap<String, Implementation>,
    mappings: Vec<IntentMapping>,
}

/// Requirement definition for intent mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    pub id: String,
    pub description: String,
    pub requirement_type: RequirementType,
    pub priority: Priority,
    pub status: RequirementStatus,
}

/// Implementation definition for intent mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Implementation {
    pub id: String,
    pub description: String,
    pub implementation_type: ImplementationType,
    pub file_path: String,
    pub line_range: Option<(usize, usize)>,
    pub status: ImplementationStatus,
}

/// Mapping between requirement and implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentMapping {
    pub requirement_id: String,
    pub implementation_id: String,
    pub mapping_type: MappingType,
    pub confidence: f64,
    pub validation_status: ValidationStatus,
}

/// Type of requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequirementType {
    Functional,
    NonFunctional,
    Security,
    Performance,
    Usability,
}

/// Type of implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplementationType {
    Function,
    Class,
    Module,
    Test,
    Documentation,
}

/// Priority level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

/// Requirement status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequirementStatus {
    Draft,
    Approved,
    Implemented,
    Tested,
    Verified,
}

/// Implementation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplementationStatus {
    Planned,
    InProgress,
    Complete,
    Tested,
    Deployed,
}

/// Type of mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MappingType {
    Direct,
    Partial,
    Indirect,
    Derived,
}

/// Validation status of mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationStatus {
    Pending,
    Valid,
    Invalid,
    NeedsReview,
}

/// Analysis result for intent mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingAnalysisResult {
    pub total_requirements: usize,
    pub total_implementations: usize,
    pub total_mappings: usize,
    pub coverage_percentage: f64,
    pub unmapped_requirements: Vec<String>,
    pub unmapped_implementations: Vec<String>,
    pub quality_score: f64,
}

/// Configuration for intent mapping analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingConfig {
    pub min_confidence_threshold: f64,
    pub enable_fuzzy_matching: bool,
    pub max_mapping_distance: usize,
    pub require_validation: bool,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            min_confidence_threshold: 0.7,
            enable_fuzzy_matching: true,
            max_mapping_distance: 100,
            require_validation: false,
        }
    }
}

impl IntentMappingSystem {
    /// Create a new intent mapping system
    pub fn new() -> Self {
        Self {
            requirements: HashMap::new(),
            implementations: HashMap::new(),
            mappings: Vec::new(),
        }
    }

    /// Add a requirement to the system
    pub fn add_requirement(&mut self, requirement: Requirement) -> Result<()> {
        self.requirements.insert(requirement.id.clone(), requirement);
        Ok(())
    }

    /// Add an implementation to the system
    pub fn add_implementation(&mut self, implementation: Implementation) -> Result<()> {
        self.implementations.insert(implementation.id.clone(), implementation);
        Ok(())
    }

    /// Create a mapping between requirement and implementation
    pub fn create_mapping(
        &mut self,
        requirement_id: String,
        implementation_id: String,
        mapping_type: MappingType,
    ) -> Result<()> {
        // Validate that both requirement and implementation exist
        if !self.requirements.contains_key(&requirement_id) {
            return Err(Error::InvalidInput(format!(
                "Requirement '{}' not found",
                requirement_id
            )));
        }

        if !self.implementations.contains_key(&implementation_id) {
            return Err(Error::InvalidInput(format!(
                "Implementation '{}' not found",
                implementation_id
            )));
        }

        // Create mapping with basic confidence score
        let confidence = match mapping_type {
            MappingType::Direct => 0.9,
            MappingType::Partial => 0.7,
            MappingType::Indirect => 0.5,
            MappingType::Derived => 0.6,
        };

        let mapping = IntentMapping {
            requirement_id,
            implementation_id,
            mapping_type,
            confidence,
            validation_status: ValidationStatus::Pending,
        };

        self.mappings.push(mapping);
        Ok(())
    }

    /// Analyze the current mappings and generate a report
    pub fn analyze_mappings(&self, config: &MappingConfig) -> Result<MappingAnalysisResult> {
        let total_requirements = self.requirements.len();
        let total_implementations = self.implementations.len();
        let total_mappings = self.mappings.len();

        // Find unmapped requirements
        let mapped_requirements: std::collections::HashSet<_> = self
            .mappings
            .iter()
            .filter(|m| m.confidence >= config.min_confidence_threshold)
            .map(|m| &m.requirement_id)
            .collect();

        let unmapped_requirements: Vec<String> = self
            .requirements
            .keys()
            .filter(|id| !mapped_requirements.contains(id))
            .cloned()
            .collect();

        // Find unmapped implementations
        let mapped_implementations: std::collections::HashSet<_> = self
            .mappings
            .iter()
            .filter(|m| m.confidence >= config.min_confidence_threshold)
            .map(|m| &m.implementation_id)
            .collect();

        let unmapped_implementations: Vec<String> = self
            .implementations
            .keys()
            .filter(|id| !mapped_implementations.contains(id))
            .cloned()
            .collect();

        // Calculate coverage percentage
        let coverage_percentage = if total_requirements > 0 {
            (mapped_requirements.len() as f64 / total_requirements as f64) * 100.0
        } else {
            0.0
        };

        // Calculate quality score based on mapping confidence and coverage
        let avg_confidence = if !self.mappings.is_empty() {
            self.mappings.iter().map(|m| m.confidence).sum::<f64>() / self.mappings.len() as f64
        } else {
            0.0
        };

        let quality_score = (coverage_percentage / 100.0 * 0.6) + (avg_confidence * 0.4);

        Ok(MappingAnalysisResult {
            total_requirements,
            total_implementations,
            total_mappings,
            coverage_percentage,
            unmapped_requirements,
            unmapped_implementations,
            quality_score,
        })
    }

    /// Get all requirements
    pub fn get_requirements(&self) -> &HashMap<String, Requirement> {
        &self.requirements
    }

    /// Get all implementations
    pub fn get_implementations(&self) -> &HashMap<String, Implementation> {
        &self.implementations
    }

    /// Get all mappings
    pub fn get_mappings(&self) -> &[IntentMapping] {
        &self.mappings
    }

    /// Validate a specific mapping
    pub fn validate_mapping(&mut self, requirement_id: &str, implementation_id: &str) -> Result<bool> {
        for mapping in &mut self.mappings {
            if mapping.requirement_id == requirement_id && mapping.implementation_id == implementation_id {
                mapping.validation_status = ValidationStatus::Valid;
                return Ok(true);
            }
        }
        Err(Error::InvalidInput("Mapping not found".to_string()))
    }

    /// Auto-discover potential mappings based on text similarity
    pub fn discover_mappings(&mut self, config: &MappingConfig) -> Result<usize> {
        let mut discovered = 0;

        if !config.enable_fuzzy_matching {
            return Ok(discovered);
        }

        // Simple text-based matching for discovery
        for (req_id, requirement) in &self.requirements {
            for (impl_id, implementation) in &self.implementations {
                // Skip if mapping already exists
                if self.mappings.iter().any(|m| {
                    m.requirement_id == *req_id && m.implementation_id == *impl_id
                }) {
                    continue;
                }

                // Simple keyword matching
                let req_words: Vec<&str> = requirement.description.to_lowercase().split_whitespace().collect();
                let impl_words: Vec<&str> = implementation.description.to_lowercase().split_whitespace().collect();

                let common_words = req_words.iter()
                    .filter(|word| impl_words.contains(word))
                    .count();

                let similarity = common_words as f64 / req_words.len().max(impl_words.len()) as f64;

                if similarity >= config.min_confidence_threshold {
                    let mapping = IntentMapping {
                        requirement_id: req_id.clone(),
                        implementation_id: impl_id.clone(),
                        mapping_type: MappingType::Indirect,
                        confidence: similarity,
                        validation_status: ValidationStatus::NeedsReview,
                    };

                    self.mappings.push(mapping);
                    discovered += 1;
                }
            }
        }

        Ok(discovered)
    }
}

impl Default for IntentMappingSystem {
    fn default() -> Self {
        Self::new()
    }
}


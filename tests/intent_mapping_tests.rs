// TODO: Re-enable when intent_mapping module is fully implemented
// This test depends on ML features that are currently disabled

/*
use rust_tree_sitter::{
    IntentMappingSystem, MappingConfig, Requirement, Implementation,
    RequirementType, ImplementationType, IntentPriority as Priority, RequirementStatus,
    ImplementationStatus, QualityMetrics, CodeElement, MappingType,
    ValidationStatus, GapType, RecommendationType
};
use std::path::PathBuf;

fn create_sample_requirement() -> Requirement {
    Requirement {
        id: "REQ-001".to_string(),
        requirement_type: RequirementType::Functional,
        description: "User authentication system with login and logout functionality".to_string(),
        priority: Priority::High,
        acceptance_criteria: vec![
            "User can login with username and password".to_string(),
            "User can logout securely".to_string(),
            "Invalid credentials are rejected".to_string(),
        ],
        stakeholders: vec!["Product Manager".to_string(), "Security Team".to_string()],
        tags: vec!["authentication".to_string(), "security".to_string()],
        status: RequirementStatus::Approved,
    }
}

fn create_sample_implementation() -> Implementation {
    Implementation {
        id: "IMPL-001".to_string(),
        implementation_type: ImplementationType::Module,
        file_path: PathBuf::from("src/auth.rs"),
        code_elements: vec![
            CodeElement {
                name: "login".to_string(),
                element_type: "function".to_string(),
                line_range: (10, 25),
                complexity: 2.5,
                test_coverage: 0.85,
            },
            CodeElement {
                name: "logout".to_string(),
                element_type: "function".to_string(),
                line_range: (30, 40),
                complexity: 1.5,
                test_coverage: 0.90,
            },
        ],
        status: ImplementationStatus::Complete,
        quality_metrics: QualityMetrics {
            coverage: 0.87,
            complexity: 2.0,
            maintainability: 0.85,
            performance: 0.90,
            security: 0.95,
        },
        documentation: Some("Authentication module providing login/logout functionality".to_string()),
    }
}

#[test]
fn test_intent_mapping_system_creation() {
    let system = IntentMappingSystem::new();
    
    // Should start with empty collections
    assert_eq!(system.requirements().len(), 0);
    assert_eq!(system.implementations().len(), 0);
    assert_eq!(system.mappings().len(), 0);
}

#[test]
fn test_intent_mapping_system_with_config() {
    let config = MappingConfig {
        confidence_threshold: 0.8,
        enable_nlp: true,
        enable_semantic_analysis: true,
        max_mapping_distance: 0.9,
        auto_validation_threshold: 0.95,
    };
    
    let system = IntentMappingSystem::with_config(config.clone());
    
    assert_eq!(system.config().confidence_threshold, 0.8);
    assert_eq!(system.config().auto_validation_threshold, 0.95);
}

#[test]
fn test_add_requirement() {
    let mut system = IntentMappingSystem::new();
    let requirement = create_sample_requirement();
    
    system.add_requirement(requirement.clone());
    
    assert_eq!(system.requirements().len(), 1);
    assert_eq!(system.requirements()[0].id, "REQ-001");
    assert_eq!(system.requirements()[0].description, requirement.description);
}

#[test]
fn test_add_multiple_requirements() {
    let mut system = IntentMappingSystem::new();
    
    let req1 = Requirement {
        id: "REQ-001".to_string(),
        requirement_type: RequirementType::Functional,
        description: "User authentication".to_string(),
        priority: Priority::High,
        acceptance_criteria: vec![],
        stakeholders: vec![],
        tags: vec![],
        status: RequirementStatus::Approved,
    };
    
    let req2 = Requirement {
        id: "REQ-002".to_string(),
        requirement_type: RequirementType::UserStory,
        description: "User profile management".to_string(),
        priority: Priority::Medium,
        acceptance_criteria: vec![],
        stakeholders: vec![],
        tags: vec![],
        status: RequirementStatus::Draft,
    };
    
    system.add_requirements(vec![req1, req2]);
    
    assert_eq!(system.requirements().len(), 2);
    assert_eq!(system.requirements()[0].id, "REQ-001");
    assert_eq!(system.requirements()[1].id, "REQ-002");
}

#[test]
fn test_keyword_extraction() {
    let system = IntentMappingSystem::new();
    let text = "User authentication system with login and logout functionality";
    
    let keywords = system.extract_keywords_public(text);
    
    // Should extract meaningful keywords and filter stop words
    assert!(keywords.contains(&"user".to_string()));
    assert!(keywords.contains(&"authentication".to_string()));
    assert!(keywords.contains(&"system".to_string()));
    assert!(keywords.contains(&"login".to_string()));
    assert!(keywords.contains(&"logout".to_string()));
    assert!(keywords.contains(&"functionality".to_string()));
    
    // Should not contain stop words
    assert!(!keywords.contains(&"with".to_string()));
    assert!(!keywords.contains(&"and".to_string()));
}

#[test]
fn test_keyword_similarity_calculation() {
    let system = IntentMappingSystem::new();
    
    let keywords1 = vec!["user".to_string(), "authentication".to_string(), "login".to_string()];
    let keywords2 = vec!["user".to_string(), "login".to_string(), "system".to_string()];
    
    let similarity = system.calculate_keyword_similarity_public(&keywords1, &keywords2);
    
    // Should calculate Jaccard similarity
    // Intersection: {user, login} = 2
    // Union: {user, authentication, login, system} = 4
    // Similarity: 2/4 = 0.5
    assert!((similarity - 0.5).abs() < 0.01);
}

#[test]
fn test_implementation_keyword_extraction() {
    let system = IntentMappingSystem::new();
    let implementation = create_sample_implementation();
    
    let keywords = system.extract_implementation_keywords_public(&implementation);
    
    // Should extract keywords from file name and code elements
    assert!(keywords.contains(&"auth".to_string()));
    assert!(keywords.contains(&"login".to_string()));
    assert!(keywords.contains(&"logout".to_string()));
}

#[test]
fn test_pattern_matching() {
    let system = IntentMappingSystem::new();
    
    let user_story = Requirement {
        id: "REQ-US-001".to_string(),
        requirement_type: RequirementType::UserStory,
        description: "As a user I want to login to access my account".to_string(),
        priority: Priority::High,
        acceptance_criteria: vec![],
        stakeholders: vec![],
        tags: vec![],
        status: RequirementStatus::Approved,
    };
    
    let api_impl = Implementation {
        id: "IMPL-API-001".to_string(),
        implementation_type: ImplementationType::API,
        file_path: PathBuf::from("src/api/auth.rs"),
        code_elements: vec![],
        status: ImplementationStatus::Complete,
        quality_metrics: QualityMetrics::default(),
        documentation: None,
    };
    
    let pattern_score = system.calculate_pattern_match_public(&user_story, &api_impl);
    
    // Should have some pattern match score for UserStory -> API
    assert!(pattern_score > 0.0);
}

#[test]
fn test_mapping_validation() {
    let mut system = IntentMappingSystem::new();
    
    let requirement = create_sample_requirement();
    let implementation = create_sample_implementation();
    
    system.add_requirement(requirement.clone());
    system.add_implementation(implementation.clone());
    
    // Create a high-confidence mapping
    let mapping = rust_tree_sitter::intent_mapping::IntentMapping {
        id: "MAP-001".to_string(),
        requirement_id: requirement.id.clone(),
        implementation_id: implementation.id.clone(),
        mapping_type: MappingType::Direct,
        confidence: 0.95,
        rationale: "High confidence mapping".to_string(),
        validation_status: ValidationStatus::NotValidated,
        last_updated: 0,
    };
    
    let validation_result = system.validate_mapping_public(&mapping).unwrap();
    
    // Should validate as valid due to high confidence and good quality metrics
    assert_eq!(validation_result, ValidationStatus::Valid);
}

#[test]
fn test_traceability_matrix_building() {
    let mut system = IntentMappingSystem::new();
    
    let requirement = create_sample_requirement();
    let implementation = create_sample_implementation();
    
    system.add_requirement(requirement.clone());
    system.add_implementation(implementation.clone());

    // Add a mapping
    system.add_mapping(rust_tree_sitter::intent_mapping::IntentMapping {
        id: "MAP-001".to_string(),
        requirement_id: requirement.id.clone(),
        implementation_id: implementation.id.clone(),
        mapping_type: MappingType::Direct,
        confidence: 0.9,
        rationale: "Test mapping".to_string(),
        validation_status: ValidationStatus::Valid,
        last_updated: 0,
    });
    
    system.build_traceability_matrix_public();

    // Should have forward and backward traceability
    assert!(system.traceability().forward_trace.contains_key(&requirement.id));
    assert!(system.traceability().backward_trace.contains_key(&implementation.id));

    // Should calculate coverage metrics
    assert_eq!(system.traceability().coverage_metrics.requirement_coverage, 1.0);
    assert_eq!(system.traceability().coverage_metrics.implementation_coverage, 1.0);
    assert_eq!(system.traceability().coverage_metrics.orphaned_requirements, 0);
    assert_eq!(system.traceability().coverage_metrics.orphaned_implementations, 0);
}

#[test]
fn test_gap_identification() {
    let mut system = IntentMappingSystem::new();
    
    // Add requirement without implementation
    let orphaned_req = Requirement {
        id: "REQ-ORPHAN".to_string(),
        requirement_type: RequirementType::Functional,
        description: "Orphaned requirement".to_string(),
        priority: Priority::Medium,
        acceptance_criteria: vec![],
        stakeholders: vec![],
        tags: vec![],
        status: RequirementStatus::Approved,
    };
    
    // Add implementation without requirement
    let orphaned_impl = Implementation {
        id: "IMPL-ORPHAN".to_string(),
        implementation_type: ImplementationType::Function,
        file_path: PathBuf::from("src/orphan.rs"),
        code_elements: vec![],
        status: ImplementationStatus::Complete,
        quality_metrics: QualityMetrics {
            coverage: 0.3, // Low coverage
            complexity: 1.0,
            maintainability: 0.8,
            performance: 0.8,
            security: 0.8,
        },
        documentation: None,
    };
    
    system.add_requirement(orphaned_req);
    system.add_implementation(orphaned_impl);

    system.build_traceability_matrix_public();
    let gaps = system.identify_gaps_public().unwrap();
    
    // Should identify gaps
    assert!(gaps.len() >= 2); // At least missing implementation and test gap
    
    let gap_types: Vec<_> = gaps.iter().map(|g| &g.gap_type).collect();
    assert!(gap_types.contains(&&GapType::MissingImplementation));
    assert!(gap_types.contains(&&GapType::MissingRequirement));
    assert!(gap_types.contains(&&GapType::TestGap));
}

#[test]
fn test_recommendation_generation() {
    let system = IntentMappingSystem::new();
    
    let gaps = vec![
        rust_tree_sitter::intent_mapping::MappingGap {
            gap_type: GapType::MissingImplementation,
            description: "Missing implementation".to_string(),
            affected_items: vec!["REQ-001".to_string()],
            severity: Priority::High,
            suggested_actions: vec![],
        },
        rust_tree_sitter::intent_mapping::MappingGap {
            gap_type: GapType::TestGap,
            description: "Low test coverage".to_string(),
            affected_items: vec!["IMPL-001".to_string()],
            severity: Priority::Medium,
            suggested_actions: vec![],
        },
    ];
    
    let recommendations = system.generate_recommendations_public(&gaps).unwrap();
    
    assert_eq!(recommendations.len(), 2);
    
    let rec_types: Vec<_> = recommendations.iter().map(|r| &r.recommendation_type).collect();
    assert!(rec_types.contains(&&RecommendationType::CreateImplementation));
    assert!(rec_types.contains(&&RecommendationType::AddTests));
}

#[test]
fn test_traceability_report() {
    let mut system = IntentMappingSystem::new();
    
    let requirement = create_sample_requirement();
    let implementation = create_sample_implementation();
    
    system.add_requirement(requirement.clone());
    system.add_implementation(implementation.clone());

    // Add valid mapping
    system.add_mapping(rust_tree_sitter::intent_mapping::IntentMapping {
        id: "MAP-001".to_string(),
        requirement_id: requirement.id.clone(),
        implementation_id: implementation.id.clone(),
        mapping_type: MappingType::Direct,
        confidence: 0.9,
        rationale: "Test mapping".to_string(),
        validation_status: ValidationStatus::Valid,
        last_updated: 0,
    });
    
    system.build_traceability_matrix_public();
    let report = system.get_traceability_report();
    
    assert_eq!(report.forward_coverage, 1.0);
    assert_eq!(report.backward_coverage, 1.0);
    assert_eq!(report.orphaned_requirements.len(), 0);
    assert_eq!(report.orphaned_implementations.len(), 0);
    assert_eq!(report.mapping_quality_score, 1.0);
}
*/

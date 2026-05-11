use rust_tree_sitter::ai::{AIFeature, AIRequest, AIResult, AIServiceBuilder};

#[tokio::main]
async fn main() -> AIResult<()> {
    println!("👨‍💻 AI-Powered Code Review Assistant");
    println!("=====================================");

    // Initialize AI service
    let ai_service = AIServiceBuilder::new()
        .with_mock_providers(true)
        .build()
        .await?;

    // Simulate a code review scenario
    let code_to_review = r#"
use std::collections::HashMap;
use std::fs;

pub struct UserManager {
    users: HashMap<String, User>,
    admin_key: String,
}

#[derive(Debug, Clone)]
pub struct User {
    id: String,
    name: String,
    email: String,
    password: String, // Plain text password - security issue!
    is_admin: bool,
}

impl UserManager {
    pub fn new(admin_key: String) -> Self {
        Self {
            users: HashMap::new(),
            admin_key,
        }
    }
    
    // Potential security vulnerability - no input validation
    pub fn create_user(&mut self, id: String, name: String, email: String, password: String) -> Result<(), String> {
        if self.users.contains_key(&id) {
            return Err("User already exists".to_string());
        }
        
        let user = User {
            id: id.clone(),
            name,
            email,
            password, // Storing plain text password!
            is_admin: false,
        };
        
        self.users.insert(id, user);
        Ok(())
    }
    
    // SQL injection vulnerable if used with database
    pub fn authenticate(&self, id: &str, password: &str) -> bool {
        if let Some(user) = self.users.get(id) {
            user.password == password // Plain text comparison
        } else {
            false
        }
    }
    
    // Admin backdoor - security risk
    pub fn make_admin(&mut self, id: &str, admin_key: &str) -> Result<(), String> {
        if admin_key == self.admin_key {
            if let Some(user) = self.users.get_mut(id) {
                user.is_admin = true;
                Ok(())
            } else {
                Err("User not found".to_string())
            }
        } else {
            Err("Invalid admin key".to_string())
        }
    }
    
    // Memory leak potential - never removes users
    pub fn get_all_users(&self) -> Vec<User> {
        self.users.values().cloned().collect()
    }
    
    // No error handling for file operations
    pub fn save_to_file(&self, filename: &str) {
        let data = serde_json::to_string(&self.users).unwrap();
        fs::write(filename, data).unwrap(); // Panics on error!
    }
}
"#;

    println!("📝 Code Under Review:");
    println!("=====================");
    println!("File: user_manager.rs");
    println!("Lines: {} lines of code", code_to_review.lines().count());

    // 1. COMPREHENSIVE SECURITY REVIEW
    println!("\n🔒 SECURITY ANALYSIS");
    println!("====================");

    let security_context = format!(
        "SECURITY CODE REVIEW\n\
        \n\
        Please perform a comprehensive security analysis of this Rust code:\n\
        \n\
        {}\n\
        \n\
        Focus on:\n\
        1. Authentication and authorization flaws\n\
        2. Data storage security issues\n\
        3. Input validation problems\n\
        4. Potential injection vulnerabilities\n\
        5. Information disclosure risks\n\
        6. Error handling security implications\n\
        \n\
        Provide specific line numbers and remediation steps.",
        code_to_review
    );

    let security_request = AIRequest::new(AIFeature::SecurityAnalysis, security_context);

    match ai_service.process_request(security_request).await {
        Ok(response) => {
            println!("🛡️  Security Vulnerabilities Found:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Security analysis failed: {}", e),
    }

    // 2. CODE QUALITY AND BEST PRACTICES
    println!("\n📊 CODE QUALITY ASSESSMENT");
    println!("===========================");

    let quality_context = format!(
        "CODE QUALITY REVIEW\n\
        \n\
        Please assess the code quality of this Rust implementation:\n\
        \n\
        {}\n\
        \n\
        Evaluate:\n\
        1. Rust idioms and best practices\n\
        2. Error handling patterns\n\
        3. Memory safety and ownership\n\
        4. API design and usability\n\
        5. Code organization and structure\n\
        6. Performance considerations\n\
        7. Maintainability and readability\n\
        \n\
        Provide a quality score (1-10) and specific improvements.",
        code_to_review
    );

    let quality_request = AIRequest::new(AIFeature::QualityAssessment, quality_context);

    match ai_service.process_request(quality_request).await {
        Ok(response) => {
            println!("📈 Code Quality Report:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Quality assessment failed: {}", e),
    }

    // 3. REFACTORING RECOMMENDATIONS
    println!("\n🔧 REFACTORING SUGGESTIONS");
    println!("===========================");

    let refactor_context = format!(
        "REFACTORING RECOMMENDATIONS\n\
        \n\
        Please provide detailed refactoring suggestions for this code:\n\
        \n\
        {}\n\
        \n\
        Focus on:\n\
        1. Security improvements (password hashing, input validation)\n\
        2. Error handling improvements (Result types, proper error propagation)\n\
        3. API design improvements (builder patterns, type safety)\n\
        4. Performance optimizations\n\
        5. Code organization (separation of concerns)\n\
        \n\
        Provide before/after code examples where helpful.",
        code_to_review
    );

    let refactor_request = AIRequest::new(AIFeature::RefactoringSuggestions, refactor_context);

    match ai_service.process_request(refactor_request).await {
        Ok(response) => {
            println!("🔄 Refactoring Recommendations:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Refactoring analysis failed: {}", e),
    }

    // 4. ARCHITECTURAL INSIGHTS
    println!("\n🏗️  ARCHITECTURAL REVIEW");
    println!("========================");

    let arch_context = format!(
        "ARCHITECTURAL ANALYSIS\n\
        \n\
        Please analyze the architectural aspects of this user management system:\n\
        \n\
        {}\n\
        \n\
        Consider:\n\
        1. Single Responsibility Principle adherence\n\
        2. Dependency injection opportunities\n\
        3. Interface segregation possibilities\n\
        4. Testability improvements\n\
        5. Scalability considerations\n\
        6. Integration patterns\n\
        \n\
        Suggest architectural improvements and design patterns.",
        code_to_review
    );

    let arch_request = AIRequest::new(AIFeature::ArchitecturalInsights, arch_context);

    match ai_service.process_request(arch_request).await {
        Ok(response) => {
            println!("🏛️  Architectural Insights:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Architectural analysis failed: {}", e),
    }

    // 5. TEST GENERATION SUGGESTIONS
    println!("\n🧪 TEST STRATEGY RECOMMENDATIONS");
    println!("=================================");

    let test_context = format!(
        "TEST GENERATION ANALYSIS\n\
        \n\
        Please suggest a comprehensive testing strategy for this code:\n\
        \n\
        {}\n\
        \n\
        Include:\n\
        1. Unit test cases for each method\n\
        2. Security test scenarios\n\
        3. Error condition testing\n\
        4. Integration test suggestions\n\
        5. Property-based testing opportunities\n\
        6. Mock/stub requirements\n\
        \n\
        Provide example test code where helpful.",
        code_to_review
    );

    let test_request = AIRequest::new(AIFeature::TestGeneration, test_context);

    match ai_service.process_request(test_request).await {
        Ok(response) => {
            println!("🧪 Testing Strategy:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Test generation failed: {}", e),
    }

    // 6. FINAL REVIEW SUMMARY
    println!("\n📋 CODE REVIEW SUMMARY");
    println!("======================");

    let summary_context = format!(
        "CODE REVIEW EXECUTIVE SUMMARY\n\
        \n\
        Please provide an executive summary of this code review:\n\
        \n\
        Code analyzed: UserManager implementation ({} lines)\n\
        \n\
        Provide:\n\
        1. Overall assessment (Approve/Request Changes/Reject)\n\
        2. Critical issues that must be fixed\n\
        3. Nice-to-have improvements\n\
        4. Estimated effort for fixes (hours/days)\n\
        5. Risk assessment (High/Medium/Low)\n\
        6. Recommendation for next steps",
        code_to_review.lines().count()
    );

    let summary_request = AIRequest::new(AIFeature::QualityAssessment, summary_context);

    match ai_service.process_request(summary_request).await {
        Ok(response) => {
            println!("📊 Review Summary:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Summary generation failed: {}", e),
    }

    println!("\n🎉 AI Code Review Complete!");
    println!("============================");
    println!("✅ Security vulnerabilities identified");
    println!("✅ Code quality assessed");
    println!("✅ Refactoring suggestions provided");
    println!("✅ Architectural insights generated");
    println!("✅ Test strategy recommended");
    println!("✅ Executive summary delivered");

    Ok(())
}

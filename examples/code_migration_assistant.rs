use rust_tree_sitter::ai::{AIServiceBuilder, AIFeature, AIRequest, AIResult};

#[tokio::main]
async fn main() -> AIResult<()> {
    println!("🔄 Multi-Language Code Migration Assistant");
    println!("==========================================");
    
    // Initialize AI service
    let ai_service = AIServiceBuilder::new()
        .with_mock_providers(true)
        .build()
        .await?;
    
    // Example: Python to Rust migration
    let python_code = r#"
import json
import hashlib
import sqlite3
from typing import Optional, List, Dict
from dataclasses import dataclass
from datetime import datetime

@dataclass
class User:
    id: int
    username: str
    email: str
    password_hash: str
    created_at: datetime
    is_active: bool = True

class UserRepository:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection = sqlite3.connect(db_path)
        self._create_tables()
    
    def _create_tables(self):
        cursor = self.connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        self.connection.commit()
    
    def create_user(self, username: str, email: str, password: str) -> Optional[User]:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor = self.connection.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
            ''', (username, email, password_hash))
            
            user_id = cursor.lastrowid
            self.connection.commit()
            
            return self.get_user_by_id(user_id)
        except sqlite3.IntegrityError:
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        
        if row:
            return User(
                id=row[0],
                username=row[1],
                email=row[2],
                password_hash=row[3],
                created_at=datetime.fromisoformat(row[4]),
                is_active=bool(row[5])
            )
        return None
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        cursor = self.connection.cursor()
        cursor.execute('''
            SELECT * FROM users 
            WHERE username = ? AND password_hash = ? AND is_active = TRUE
        ''', (username, password_hash))
        
        row = cursor.fetchone()
        if row:
            return User(
                id=row[0],
                username=row[1],
                email=row[2],
                password_hash=row[3],
                created_at=datetime.fromisoformat(row[4]),
                is_active=bool(row[5])
            )
        return None
"#;

    println!("🐍 Source Code (Python):");
    println!("========================");
    println!("Lines: {}", python_code.lines().count());
    println!("Features: SQLite integration, user management, authentication");
    
    // 1. ANALYZE SOURCE CODE
    println!("\n🔍 PHASE 1: Source Code Analysis");
    println!("=================================");
    
    let analysis_context = format!(
        "SOURCE CODE ANALYSIS\n\
        \n\
        Please analyze this Python code for migration to Rust:\n\
        \n\
        {}\n\
        \n\
        Identify:\n\
        1. Core functionality and business logic\n\
        2. External dependencies (sqlite3, hashlib, etc.)\n\
        3. Data structures and their relationships\n\
        4. Error handling patterns\n\
        5. Concurrency considerations\n\
        6. Performance characteristics\n\
        7. Security implications",
        python_code
    );
    
    let analysis_request = AIRequest::new(AIFeature::CodeExplanation, analysis_context);
    
    match ai_service.process_request(analysis_request).await {
        Ok(response) => {
            println!("📊 Source Code Analysis:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Analysis failed: {}", e),
    }
    
    // 2. MIGRATION STRATEGY
    println!("\n🗺️  PHASE 2: Migration Strategy");
    println!("===============================");
    
    let strategy_context = format!(
        "MIGRATION STRATEGY PLANNING\n\
        \n\
        Source: Python code with SQLite database operations\n\
        Target: Rust with equivalent functionality\n\
        \n\
        Python code to migrate:\n{}\n\
        \n\
        Please provide:\n\
        1. Step-by-step migration plan\n\
        2. Rust crate recommendations (sqlx, serde, chrono, etc.)\n\
        3. Architecture adaptations needed\n\
        4. Error handling strategy (Result types)\n\
        5. Memory safety considerations\n\
        6. Performance optimization opportunities\n\
        7. Testing strategy for migration validation",
        python_code
    );
    
    let strategy_request = AIRequest::new(AIFeature::ArchitecturalInsights, strategy_context);
    
    match ai_service.process_request(strategy_request).await {
        Ok(response) => {
            println!("🎯 Migration Strategy:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Strategy planning failed: {}", e),
    }
    
    // 3. RUST CODE GENERATION
    println!("\n🦀 PHASE 3: Rust Code Generation");
    println!("=================================");
    
    let generation_context = format!(
        "RUST CODE GENERATION\n\
        \n\
        Please convert this Python code to idiomatic Rust:\n\
        \n\
        {}\n\
        \n\
        Requirements:\n\
        1. Use proper Rust error handling (Result<T, E>)\n\
        2. Implement appropriate traits (Debug, Clone, etc.)\n\
        3. Use async/await for database operations\n\
        4. Include proper documentation\n\
        5. Follow Rust naming conventions\n\
        6. Use appropriate crates (sqlx, serde, chrono, tokio)\n\
        7. Implement proper lifetime management\n\
        8. Add comprehensive error types",
        python_code
    );
    
    let generation_request = AIRequest::new(AIFeature::RefactoringSuggestions, generation_context);
    
    match ai_service.process_request(generation_request).await {
        Ok(response) => {
            println!("🔧 Generated Rust Code:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Code generation failed: {}", e),
    }
    
    // 4. SECURITY COMPARISON
    println!("\n🔒 PHASE 4: Security Analysis");
    println!("==============================");
    
    let security_context = format!(
        "SECURITY MIGRATION ANALYSIS\n\
        \n\
        Original Python code:\n{}\n\
        \n\
        Please analyze:\n\
        1. Security vulnerabilities in the original Python code\n\
        2. How Rust's type system improves security\n\
        3. Memory safety improvements\n\
        4. SQL injection prevention strategies\n\
        5. Password hashing improvements\n\
        6. Error information leakage prevention\n\
        7. Concurrency safety in Rust vs Python",
        python_code
    );
    
    let security_request = AIRequest::new(AIFeature::SecurityAnalysis, security_context);
    
    match ai_service.process_request(security_request).await {
        Ok(response) => {
            println!("🛡️  Security Improvements:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Security analysis failed: {}", e),
    }
    
    // 5. TESTING STRATEGY
    println!("\n🧪 PHASE 5: Testing Strategy");
    println!("=============================");
    
    let testing_context = format!(
        "MIGRATION TESTING STRATEGY\n\
        \n\
        Original Python implementation:\n{}\n\
        \n\
        Please provide:\n\
        1. Unit test cases for Rust implementation\n\
        2. Integration tests for database operations\n\
        3. Property-based testing suggestions\n\
        4. Performance benchmarking tests\n\
        5. Migration validation tests (Python vs Rust behavior)\n\
        6. Error condition testing\n\
        7. Concurrency testing strategies",
        python_code
    );
    
    let testing_request = AIRequest::new(AIFeature::TestGeneration, testing_context);
    
    match ai_service.process_request(testing_request).await {
        Ok(response) => {
            println!("🧪 Testing Strategy:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Testing strategy failed: {}", e),
    }
    
    // 6. PERFORMANCE ANALYSIS
    println!("\n⚡ PHASE 6: Performance Optimization");
    println!("====================================");
    
    let performance_context = format!(
        "PERFORMANCE OPTIMIZATION ANALYSIS\n\
        \n\
        Python baseline:\n{}\n\
        \n\
        Analyze:\n\
        1. Expected performance improvements in Rust\n\
        2. Memory usage optimizations\n\
        3. Database connection pooling strategies\n\
        4. Async/await performance benefits\n\
        5. Zero-copy optimizations\n\
        6. Compilation optimizations\n\
        7. Benchmarking recommendations",
        python_code
    );
    
    let performance_request = AIRequest::new(AIFeature::QualityAssessment, performance_context);
    
    match ai_service.process_request(performance_request).await {
        Ok(response) => {
            println!("⚡ Performance Analysis:");
            println!("{}", response.content);
        }
        Err(e) => println!("❌ Performance analysis failed: {}", e),
    }
    
    println!("\n🎉 Code Migration Analysis Complete!");
    println!("====================================");
    println!("✅ Source code analyzed");
    println!("✅ Migration strategy developed");
    println!("✅ Rust code generated");
    println!("✅ Security improvements identified");
    println!("✅ Testing strategy created");
    println!("✅ Performance optimizations planned");
    
    Ok(())
}

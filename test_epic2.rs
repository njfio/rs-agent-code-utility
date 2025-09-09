//! Test file to demonstrate Epic 2: Intelligent Vulnerability Detection
//!
//! This file contains various security scenarios to test the enhanced
//! AST-based security analysis with taint analysis, ML filtering, and
//! advanced language-specific detection rules.

use std::collections::HashMap;

/// Test case 1: SQL Injection with taint analysis
pub fn vulnerable_sql_query(user_input: &str) -> Result<(), String> {
    let query = format!("SELECT * FROM users WHERE id = {}", user_input);
    // This should be detected as SQL injection with high confidence
    println!("Executing: {}", query);
    Ok(())
}

/// Test case 2: Safe SQL query with proper sanitization
pub fn safe_sql_query(user_input: &str) -> Result<(), String> {
    let user_id: i32 = user_input.parse().map_err(|_| "Invalid ID")?;
    let query = format!("SELECT * FROM users WHERE id = {}", user_id);
    // This should be flagged as lower risk due to type conversion
    println!("Executing: {}", query);
    Ok(())
}

/// Test case 3: Command injection vulnerability
pub fn vulnerable_command_execution(user_cmd: &str) -> Result<(), String> {
    let full_cmd = format!("ls {}", user_cmd);
    std::process::Command::new("sh")
        .arg("-c")
        .arg(&full_cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Test case 4: XSS vulnerability in HTML generation
pub fn vulnerable_html_output(user_data: &str) -> String {
    format!("<div>User: {}</div>", user_data) // Should detect innerHTML-like vulnerability
}

/// Test case 5: Hardcoded secret (should be filtered by ML)
const API_KEY: &str = "sk-1234567890abcdef"; // This should be filtered as test code

/// Test case 6: Unsafe macro usage
macro_rules! dangerous_macro {
    ($input:expr) => {
        println!("{}", $input); // Potential format string vulnerability
    };
}

pub fn test_macro_usage(user_input: &str) {
    dangerous_macro!(user_input);
}

/// Test case 7: Improper error handling
pub fn risky_unwrap(data: Option<&str>) -> &str {
    data.unwrap() // Should be flagged for potential panic
}

/// Test case 8: Race condition with static mutable
static mut COUNTER: i32 = 0;

pub fn increment_counter() {
    unsafe {
        COUNTER += 1; // Should be flagged for race condition potential
    }
}

/// Test case 9: Weak cryptography
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub fn weak_hash(data: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish() // Should be flagged for weak cryptography
}

/// Test case 10: Path traversal vulnerability
pub fn read_file(user_path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(user_path) // Should detect path traversal
}

/// Test case 11: Safe file reading with validation
pub fn safe_read_file(user_path: &str) -> Result<String, std::io::Error> {
    // Basic path validation
    if user_path.contains("..") || user_path.contains("/") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid path",
        ));
    }
    std::fs::read_to_string(user_path)
}

/// Test case 12: Data flow analysis example
pub fn data_flow_example(user_input: &str) -> String {
    let processed = process_input(user_input);
    let result = format_output(processed);
    result
}

fn process_input(input: &str) -> String {
    input.to_uppercase() // This should be tracked in data flow
}

fn format_output(data: String) -> String {
    format!("<p>{}</p>", data) // Should detect potential XSS
}

/// Test case 13: Configuration with secrets (should be filtered)
pub struct Config {
    pub database_url: String,
    pub api_key: String,
    pub debug: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: "postgres://user:pass@localhost/db".to_string(),
            api_key: "test_key_123".to_string(), // Should be filtered as test
            debug: true,
        }
    }
}

/// Test case 14: Authentication bypass attempt
pub fn check_admin_access(user: &User, action: &str) -> bool {
    // Missing authorization check - should be flagged
    if user.role == "admin" {
        return true;
    }
    false
}

pub struct User {
    pub id: i32,
    pub role: String,
    pub permissions: Vec<String>,
}

/// Test case 15: Insecure deserialization
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct UserData {
    pub name: String,
    pub admin: bool,
}

pub fn deserialize_user(json_data: &str) -> Result<UserData, serde_json::Error> {
    serde_json::from_str(json_data) // Should flag for insecure deserialization
}

/// Test case 16: Timing attack vulnerability
pub fn insecure_password_check(input: &str) -> bool {
    let correct_password = "secret123";
    input == correct_password // Should flag for timing attack vulnerability
}

/// Test case 17: Information disclosure
pub fn error_message(user_id: i32) -> String {
    match get_user(user_id) {
        Some(user) => format!("User: {}", user.name),
        None => format!("User {} not found with role {}", user_id, "admin"), // Information disclosure
    }
}

fn get_user(_id: i32) -> Option<User> {
    None
}

/// Test case 18: Race condition with shared state
use std::sync::Mutex;

static SHARED_DATA: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());

pub fn update_shared_data(key: String, value: String) {
    let mut data = SHARED_DATA.lock().unwrap();
    data.insert(key, value); // Should be analyzed for race condition potential
}

/// Test case 19: Unvalidated redirect
pub fn redirect_user(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Should flag for open redirect vulnerability
    println!("Redirecting to: {}", url);
    Ok(())
}

/// Test case 20: Memory safety issue
pub fn unsafe_pointer_usage() {
    let mut value = 42;
    let ptr = &mut value as *mut i32;
    unsafe {
        *ptr = 100; // Should be flagged for unsafe pointer usage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_sql() {
        // This test should trigger SQL injection detection
        let result = vulnerable_sql_query("1; DROP TABLE users;");
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_sql() {
        // This should have lower risk due to validation
        let result = safe_sql_query("123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_hardcoded_secret() {
        // This should be filtered by ML as test code
        assert_eq!(API_KEY, "sk-1234567890abcdef");
    }

    #[test]
    fn test_weak_crypto() {
        let hash = weak_hash("test");
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_data_flow() {
        let result = data_flow_example("<script>alert('xss')</script>");
        assert!(result.contains("<script>"));
    }
}

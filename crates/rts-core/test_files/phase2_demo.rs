// Phase 2 Demo File - Showcasing Advanced Intelligence Features
// This file contains various code patterns to demonstrate the new capabilities

use std::collections::HashMap;
use sha2::{Digest, Sha256};
use std::env;

// Example with potential security vulnerabilities
pub struct UserService {
    api_key: String,
    users: HashMap<String, User>,
}

pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    password: String, // Should be hashed
}

impl UserService {
    pub fn new() -> Self {
        let api_key = env::var("API_KEY").unwrap_or_default();
        Self {
            api_key,
            users: HashMap::new(),
        }
    }
    
    // Long method that could be refactored (code smell)
    pub fn authenticate_user(&self, username: &str, password: &str) -> Result<User, String> {
        // Input validation missing (security issue)
        let user = self.users.get(username);
        
        match user {
            Some(u) => {
                if u.password == Self::hash_static(password) {
                    // TODO: Add proper logging
                    println!("User authenticated: {}", username);
                    Ok(u.clone())
                } else {
                    Err("Invalid credentials".to_string())
                }
            }
            None => {
                Err("User not found".to_string())
            }
        }
    }
    
    // Performance issue - inefficient string concatenation
    pub fn generate_user_report(&self) -> String {
        let mut report = String::with_capacity(self.users.len() * 32);
        for (id, user) in &self.users {
            use std::fmt::Write;
            let _ = writeln!(report, "User {}: {} ({})", id, user.name, user.email);
        }
        report
    }
    
    // Duplicate code pattern (code smell)
    pub fn create_admin_user(&self, name: String, email: String) -> User {
        User {
            id: format!("admin_{}", name),
            name,
            email,
            password: "admin123".to_string(), // Hardcoded password (security issue)
        }
    }
    
    // More duplicate code (code smell)
    pub fn create_regular_user(&self, name: String, email: String) -> User {
        User {
            id: format!("user_{}", name),
            name: name.clone(),
            email: email.clone(),
            password: "user123".to_string(), // Hardcoded password (security issue)
        }
    }
    
    // Potential SQL injection vulnerability
    pub fn find_user_by_query(&self, query: &str) -> Vec<User> {
        // This would be vulnerable if it was actual SQL
        let sql = "SELECT * FROM users WHERE name = ?";
        println!("Executing query: {} with param {}", sql, query);
        
        // Simplified implementation
        self.users.values().cloned().collect()
    }
    
    // Weak cryptographic function usage
    pub fn hash_password(&self, password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    fn hash_static(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

// Factory pattern opportunity
pub struct UserFactory;

impl UserFactory {
    pub fn create_user(user_type: &str, name: String, email: String) -> User {
        match user_type {
            "admin" => User {
                id: format!("admin_{}", name),
                name,
                email,
                password: "admin123".to_string(),
            },
            "regular" => User {
                id: format!("user_{}", name),
                name,
                email,
                password: "user123".to_string(),
            },
            _ => panic!("Unknown user type"), // Poor error handling
        }
    }
}

// Observer pattern opportunity
pub trait UserEventListener {
    fn on_user_created(&self, user: &User);
    fn on_user_deleted(&self, user_id: &str);
}

pub struct UserEventManager {
    listeners: Vec<Box<dyn UserEventListener>>,
}

impl UserEventManager {
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }
    
    pub fn add_listener(&mut self, listener: Box<dyn UserEventListener>) {
        self.listeners.push(listener);
    }
    
    pub fn notify_user_created(&self, user: &User) {
        for listener in &self.listeners {
            listener.on_user_created(user);
        }
    }
}

// Modernization opportunity - old-style error handling
pub fn process_user_data(data: &str) -> String {
    let parsed = data.parse::<i32>().unwrap(); // Should use expect() or proper error handling
    format!("Processed: {}", parsed)
}

// Performance optimization opportunity - vector without capacity
pub fn collect_user_ids(users: &[User]) -> Vec<String> {
    let mut ids = Vec::with_capacity(users.len()); // Optimized capacity
    for user in users {
        ids.push(user.id.clone());
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_user_creation() {
        let service = UserService::new();
        assert_eq!(service.users.len(), 0);
    }
    
    // TODO: Add more comprehensive tests
    // FIXME: Test coverage is insufficient
}

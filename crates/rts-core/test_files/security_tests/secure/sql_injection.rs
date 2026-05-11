// Secure SQL injection example
use std::io;

fn main() {
    println!("Enter username:");
    let mut username = String::new();
    io::stdin().read_line(&mut username).unwrap();
    let username = username.trim();

    println!("Enter password:");
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();
    let password = password.trim();

    // SECURE: Use parameterized query
    let query = "SELECT * FROM users WHERE username = ? AND password = ?";
    println!(
        "Executing query: {} with params: {}, {}",
        query, username, password
    );

    // Simulate database execution with parameters
    execute_query(query, &[username, password]);
}

fn execute_query(query: &str, params: &[&str]) {
    // In a real scenario, this would use prepared statements
    println!(
        "Query executed securely: {} with params: {:?}",
        query, params
    );
}

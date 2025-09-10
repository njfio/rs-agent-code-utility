// Vulnerable SQL injection example
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

    // VULNERABLE: Direct string concatenation in SQL query
    let query = format!("SELECT * FROM users WHERE username = '{}' AND password = '{}'", username, password);
    println!("Executing query: {}", query);

    // Simulate database execution
    execute_query(&query);
}

fn execute_query(query: &str) {
    // In a real scenario, this would execute the query
    println!("Query executed: {}", query);
}

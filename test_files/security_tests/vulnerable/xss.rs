// Vulnerable XSS example
use std::io;

fn main() {
    println!("Enter your name:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).unwrap();
    let name = name.trim();

    // VULNERABLE: Direct insertion into HTML without escaping
    let html = format!("<html><body><h1>Hello, {}!</h1></body></html>", name);
    println!("Generated HTML: {}", html);
}

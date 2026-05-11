// Secure XSS example
use std::io;

fn main() {
    println!("Enter your name:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).unwrap();
    let name = name.trim();

    // SECURE: Escape HTML characters
    let escaped_name = escape_html(name);
    let html = format!(
        "<html><body><h1>Hello, {}!</h1></body></html>",
        escaped_name
    );
    println!("Generated HTML: {}", html);
}

fn escape_html(input: &str) -> String {
    input
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
}
use std::io;

fn main() {
    println!("Enter your name:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).unwrap();
    let name = name.trim();

    // SECURE: Escape HTML characters
    let escaped_name = escape_html(name);
    let html = format!(
        "<html><body><h1>Hello, {}!</h1></body></html>",
        escaped_name
    );
    println!("Generated HTML: {}", html);
}

fn escape_html(input: &str) -> String {
    input
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
}
use std::io;

fn main() {
    println!("Enter your name:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).unwrap();
    let name = name.trim();

    // SECURE: Escape HTML characters
    let escaped_name = escape_html(name);
    let html = format!(
        "<html><body><h1>Hello, {}!</h1></body></html>",
        escaped_name
    );
    println!("Generated HTML: {}", html);
}

fn escape_html(input: &str) -> String {
    input
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
}

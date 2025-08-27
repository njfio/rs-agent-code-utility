// Simple test to verify rate limiter functionality
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing rate limiter implementation...");
    
    // Test basic rate limiting
    let config = rust_tree_sitter::infrastructure::rate_limiter::RateLimitConfig {
        service_name: "test".to_string(),
        requests_per_minute: 60,
        burst_size: Some(10),
        enable_backoff: true,
        max_backoff_duration: Duration::from_secs(60),
    };
    
    let limiter = rust_tree_sitter::infrastructure::rate_limiter::ServiceRateLimiter::new(config)?;
    
    // Test getting stats
    let stats = limiter.get_stats();
    println!("Initial stats: {:?}", stats);
    
    // Test permit checking
    let result = limiter.check_permit();
    println!("Permit check result: {:?}", result);
    
    // Test stats after request
    let stats = limiter.get_stats();
    println!("Stats after request: {:?}", stats);
    
    println!("Rate limiter test completed successfully!");
    Ok(())
}

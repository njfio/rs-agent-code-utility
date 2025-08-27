//! Real HTTP client infrastructure with proper error handling,
//! authentication, rate limiting, and retry mechanisms.

use reqwest::{Client, StatusCode};
use serde::{Serialize, Deserialize};
use std::time::Duration;
use tracing::{debug, warn, error};
// Replaced external Backoff usage with a small local exponential backoff
use rand::{thread_rng, Rng};
use anyhow::{Result, anyhow};

/// HTTP client with built-in retry, timeout, and rate limiting
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    default_timeout: Duration,
    max_retries: usize,
}

/// HTTP request configuration
#[derive(Debug, Clone)]
pub struct RequestConfig {
    pub timeout: Option<Duration>,
    pub retries: Option<usize>,
    pub headers: Vec<(String, String)>,
    pub auth: Option<AuthConfig>,
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub enum AuthConfig {
    Bearer(String),
    ApiKey { key: String, header: String },
    Basic { username: String, password: String },
}

/// HTTP response wrapper with additional metadata
#[derive(Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub body: String,
    pub url: String,
    pub duration: Duration,
}

/// Rate limiter for API calls
pub struct RateLimiter {
    limiter: governor::RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
        governor::middleware::NoOpMiddleware,
    >,
}

impl HttpClient {
    /// Create a new HTTP client with default configuration
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("rust-tree-sitter/0.3.0")
            .build()?;

        Ok(Self {
            client,
            default_timeout: Duration::from_secs(30),
            max_retries: 3,
        })
    }

    /// Create a new HTTP client with custom configuration
    pub fn with_config(timeout: Duration, max_retries: usize) -> Result<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("rust-tree-sitter/0.3.0")
            .build()?;

        Ok(Self {
            client,
            default_timeout: timeout,
            max_retries,
        })
    }

    /// Perform a GET request with retry logic
    pub async fn get(&self, url: &str, config: Option<RequestConfig>) -> Result<HttpResponse> {
        self.request("GET", url, None::<&()>, config).await
    }

    /// Perform a POST request with retry logic
    pub async fn post<T: Serialize>(&self, url: &str, body: Option<&T>, config: Option<RequestConfig>) -> Result<HttpResponse> {
        self.request("POST", url, body, config).await
    }

    /// Perform a generic HTTP request with retry logic
    async fn request<T: Serialize>(&self, method: &str, url: &str, body: Option<&T>, config: Option<RequestConfig>) -> Result<HttpResponse> {
        let config = config.unwrap_or_default();
        let timeout = config.timeout.unwrap_or(self.default_timeout);
        let max_retries = config.retries.unwrap_or(self.max_retries);

        // Local exponential backoff with jitter: starts at 100ms, caps at 5s
        let backoff_min = Duration::from_millis(100);
        let backoff_max = Duration::from_secs(5);

        for attempt in 0..=max_retries {
            let start_time = std::time::Instant::now();
            
            match self.execute_request(method, url, body, &config, timeout).await {
                Ok(response) => {
                    let duration = start_time.elapsed();
                    debug!("HTTP {} {} completed in {:?} (attempt {})", method, url, duration, attempt + 1);
                    return Ok(response);
                }
                Err(e) if attempt < max_retries && self.should_retry(&e) => {
                    // Compute exponential delay with jitter
                    let shift = attempt.min(20) as u32; // cap at 2^20
                    let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
                    let min_nanos = backoff_min.as_nanos();
                    let mut delay_nanos = min_nanos.saturating_mul(factor as u128);
                    let max_nanos = backoff_max.as_nanos();
                    if delay_nanos > max_nanos { delay_nanos = max_nanos; }
                    // jitter in [0.5, 1.5)
                    let mut rng = thread_rng();
                    let jitter_factor: f64 = rng.gen_range(0.5..1.5);
                    let jittered = (delay_nanos as f64 * jitter_factor) as u128;
                    let jittered = if jittered > max_nanos { max_nanos } else { jittered };
                    let delay = Duration::from_nanos(jittered as u64);
                    warn!("HTTP {} {} failed (attempt {}), retrying in {:?}: {}", method, url, attempt + 1, delay, e);
                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    error!("HTTP {} {} failed permanently (attempt {}): {}", method, url, attempt + 1, e);
                    return Err(e);
                }
            }
        }

        Err(anyhow!(
            "Max retries ({}) exceeded for {} {}: All retry attempts failed",
            self.max_retries, method, url
        ))
    }

    /// Execute a single HTTP request
    async fn execute_request<T: Serialize>(
        &self,
        method: &str,
        url: &str,
        body: Option<&T>,
        config: &RequestConfig,
        timeout: Duration,
    ) -> Result<HttpResponse> {
        let mut request_builder = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            "DELETE" => self.client.delete(url),
            _ => return Err(anyhow!(
                "Unsupported HTTP method '{}': expected GET, POST, PUT, or DELETE",
                method
            )),
        };

        // Add timeout
        request_builder = request_builder.timeout(timeout);

        // Add headers
        for (key, value) in &config.headers {
            request_builder = request_builder.header(key, value);
        }

        // Add authentication
        if let Some(auth) = &config.auth {
            request_builder = match auth {
                AuthConfig::Bearer(token) => request_builder.bearer_auth(token),
                AuthConfig::ApiKey { key, header } => request_builder.header(header, key),
                AuthConfig::Basic { username, password } => request_builder.basic_auth(username, Some(password)),
            };
        }

        // Add body for POST/PUT requests
        if let Some(body_data) = body {
            request_builder = request_builder.json(body_data);
        }

        // Execute request
        let response = request_builder.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let url = response.url().to_string();

        // Check for HTTP errors
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "HTTP {} error for {}: {}",
                status, url, error_body
            ));
        }

        let body = response.text().await?;

        Ok(HttpResponse {
            status,
            headers,
            body,
            url,
            duration: Duration::from_secs(0), // Will be set by caller
        })
    }

    /// Determine if an error should trigger a retry
    fn should_retry(&self, error: &anyhow::Error) -> bool {
        // Retry on network errors, timeouts, and certain HTTP status codes
        if let Some(reqwest_error) = error.downcast_ref::<reqwest::Error>() {
            return reqwest_error.is_timeout() || 
                   reqwest_error.is_connect() ||
                   reqwest_error.is_request();
        }

        // Check for specific HTTP status codes that should be retried
        let error_str = error.to_string();
        error_str.contains("500") || // Internal Server Error
        error_str.contains("502") || // Bad Gateway
        error_str.contains("503") || // Service Unavailable
        error_str.contains("504") || // Gateway Timeout
        error_str.contains("429")    // Too Many Requests
    }
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            timeout: None,
            retries: None,
            headers: Vec::new(),
            auth: None,
        }
    }
}

impl RateLimiter {
    /// Create a new rate limiter with the specified rate (requests per minute)
    pub fn new(requests_per_minute: u32) -> Self {
        use governor::{Quota, RateLimiter as GovRateLimiter};
        use std::num::NonZeroU32;

        let quota = Quota::per_minute(
            NonZeroU32::new(requests_per_minute.max(1))
                .expect("Rate limit creation failed: requests_per_minute.max(1) should always be >= 1, but NonZeroU32::new returned None")
        );
        let limiter = GovRateLimiter::direct(quota);

        Self { limiter }
    }

    /// Wait until a request can be made (respecting rate limits)
    pub async fn wait_for_permit(&self) -> Result<()> {
        self.limiter.until_ready().await;
        Ok(())
    }

    /// Check if a request can be made immediately
    pub fn check_permit(&self) -> bool {
        self.limiter.check().is_ok()
    }
}

/// HTTP client builder for easy configuration
pub struct HttpClientBuilder {
    timeout: Duration,
    max_retries: usize,
    user_agent: String,
}

impl HttpClientBuilder {
    /// Create a new HTTP client builder with default settings
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_retries: 3,
            user_agent: "rust-tree-sitter/0.3.0".to_string(),
        }
    }

    /// Set the request timeout duration
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum number of retry attempts for failed requests
    pub fn max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Set the User-Agent header for requests
    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Build the HTTP client with the configured settings
    pub fn build(self) -> Result<HttpClient> {
        let client = Client::builder()
            .timeout(self.timeout)
            .user_agent(&self.user_agent)
            .build()?;

        Ok(HttpClient {
            client,
            default_timeout: self.timeout,
            max_retries: self.max_retries,
        })
    }
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility functions for common HTTP operations
pub mod utils {
    use super::*;

    /// Parse JSON response body into the specified type
    ///
    /// # Arguments
    /// * `response` - The HTTP response containing JSON data
    ///
    /// # Returns
    /// * `Result<T>` - The parsed object or an error if parsing fails
    pub fn parse_json<T: for<'de> Deserialize<'de>>(response: &HttpResponse) -> Result<T> {
        serde_json::from_str(&response.body)
            .map_err(|e| anyhow!(
                "Failed to parse JSON response: {}. Ensure the response contains valid JSON data",
                e
            ))
    }

    /// Check if response indicates rate limiting
    ///
    /// Checks both the HTTP status code (429) and rate limit headers
    ///
    /// # Arguments
    /// * `response` - The HTTP response to check
    ///
    /// # Returns
    /// * `bool` - True if the response indicates rate limiting
    pub fn is_rate_limited(response: &HttpResponse) -> bool {
        response.status == StatusCode::TOO_MANY_REQUESTS ||
        response.headers.get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
            .map(|remaining| remaining == 0)
            .unwrap_or(false)
    }

    /// Extract rate limit information from response headers
    ///
    /// Parses standard rate limit headers to extract remaining requests and reset time
    ///
    /// # Arguments
    /// * `response` - The HTTP response containing rate limit headers
    ///
    /// # Returns
    /// * `Option<RateLimitInfo>` - Rate limit info if headers are present and valid
    pub fn extract_rate_limit_info(response: &HttpResponse) -> Option<RateLimitInfo> {
        let remaining = response.headers.get("x-ratelimit-remaining")?
            .to_str().ok()?
            .parse().ok()?;
        
        let reset = response.headers.get("x-ratelimit-reset")?
            .to_str().ok()?
            .parse().ok()?;

        Some(RateLimitInfo { remaining, reset })
    }
}

/// Rate limit information from API response headers
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub remaining: u32,
    pub reset: u64, // Unix timestamp
}

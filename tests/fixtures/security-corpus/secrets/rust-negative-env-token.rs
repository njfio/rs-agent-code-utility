fn read_secret() -> Result<String, std::env::VarError> {
    std::env::var("API_TOKEN")
}

fn find_user(user_input: &str) {
    let query = "SELECT * FROM users WHERE id = '".to_string() + user_input + "'";
    let _ = execute_query(query);
}

fn execute_query(_query: String) -> Vec<String> {
    Vec::new()
}

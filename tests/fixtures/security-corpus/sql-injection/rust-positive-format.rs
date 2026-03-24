fn find_user(user_input: &str) {
    let _rows = execute_query(format!(
        "SELECT * FROM users WHERE id = '{}'",
        user_input
    ));
}

fn execute_query(_query: String) -> Vec<String> {
    Vec::new()
}

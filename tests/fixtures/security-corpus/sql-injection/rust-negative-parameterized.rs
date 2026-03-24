fn find_user(user_input: &str) {
    let query = "SELECT * FROM users WHERE id = ?";
    execute_prepared(query, &[user_input]);
}

fn execute_prepared(_query: &str, _params: &[&str]) {}

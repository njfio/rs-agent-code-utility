fn list_users() {
    let query = "SELECT * FROM users ORDER BY created_at DESC";
    execute(query);
}

fn execute(_query: &str) {}

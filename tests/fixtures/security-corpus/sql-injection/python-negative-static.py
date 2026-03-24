def list_users(cursor):
    query = "SELECT * FROM users ORDER BY created_at DESC"
    return cursor.execute(query)

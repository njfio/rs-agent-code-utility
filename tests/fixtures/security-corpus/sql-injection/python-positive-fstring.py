def find_user(cursor, user_input):
    query = f"SELECT * FROM users WHERE id = '{user_input}'"
    return cursor.execute(query)

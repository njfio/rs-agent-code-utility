def find_user(cursor, user_input):
    query = "SELECT * FROM users WHERE id = '%s'" % user_input
    return cursor.execute(query)

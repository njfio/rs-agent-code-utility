def find_user(cursor, user_input):
    query = "SELECT * FROM users WHERE id = '{}'".format(user_input)
    return cursor.execute(query)

def find_user(cursor, user_input):
    return cursor.execute(
        "SELECT * FROM users WHERE id = %s",
        (user_input,),
    )

function findUser(userInput) {
  return queryDatabase("SELECT * FROM users WHERE id = '" + userInput + "'");
}

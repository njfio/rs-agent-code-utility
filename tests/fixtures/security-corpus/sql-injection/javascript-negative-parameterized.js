function findUser(userInput) {
  return executePrepared("SELECT * FROM users WHERE id = ?", [userInput]);
}

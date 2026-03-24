function runCommand(userInput) {
  return spawn("ls", [userInput]);
}

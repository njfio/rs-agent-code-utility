function runCommand(userInput) {
  return child_process.execSync("ls " + userInput);
}

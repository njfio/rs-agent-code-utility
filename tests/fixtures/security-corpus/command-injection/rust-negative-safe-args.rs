use std::process::Command;

fn run_command(user_input: &str) {
    let _ = Command::new("ls").arg(user_input).status();
}

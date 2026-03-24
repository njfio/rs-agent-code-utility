use std::process::Command;

fn run_command(user_input: &str) {
    let _ = Command::new("sh").arg("-c").arg(user_input).status();
}

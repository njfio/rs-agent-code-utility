import subprocess


def run_command(user_input):
    return subprocess.run(["ls", user_input], check=True)

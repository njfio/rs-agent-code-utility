import subprocess


def run_command(user_input):
    return subprocess.Popen(["ls", user_input])

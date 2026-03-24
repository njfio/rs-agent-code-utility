import subprocess


def run_command(user_input):
    return subprocess.check_output("ls " + user_input, shell=True)

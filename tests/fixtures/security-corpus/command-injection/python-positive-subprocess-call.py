import subprocess


def run_command(user_input):
    return subprocess.call("ls " + user_input, shell=True)

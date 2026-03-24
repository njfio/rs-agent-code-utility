import os


def read_secret():
    return os.getenv("API_TOKEN")

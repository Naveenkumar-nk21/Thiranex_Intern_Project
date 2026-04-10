import os


def ensure_directories():
    os.makedirs("models", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
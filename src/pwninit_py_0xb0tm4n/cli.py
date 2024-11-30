from main import pwninit
from pathlib import Path


def main():
    path = Path().resolve()
    exit(pwninit(path))

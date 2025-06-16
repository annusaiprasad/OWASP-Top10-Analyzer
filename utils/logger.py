# utils/logger.py

import sys

def info(msg):
    print(f"[INFO] {msg}")

def warn(msg):
    print(f"\033[93m[WARNING] {msg}\033[0m", file=sys.stderr)

def error(msg):
    print(f"\033[91m[ERROR] {msg}\033[0m", file=sys.stderr)

def success(msg):
    print(f"\033[92m[SUCCESS] {msg}\033[0m")

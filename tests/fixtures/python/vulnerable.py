"""Python vulnerable code for multi-language detection tests."""
import os
import pickle
import subprocess


def search_user(name):
    """SQL Injection via string concatenation."""
    sql = "SELECT * FROM users WHERE name='" + name + "'"
    conn.execute(sql)
    return conn.fetchall()


def run_command(cmd):
    """Command Injection via subprocess with shell=True."""
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout


def load_data(data):
    """Unsafe Deserialization via pickle."""
    return pickle.loads(data)


def read_file(path):
    """Path Traversal via open with user input."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def execute_code(code):
    """Dangerous Code Execution via eval."""
    return eval(code)


# Hardcoded secret
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DB_PASSWORD = "super_secret_password_123"

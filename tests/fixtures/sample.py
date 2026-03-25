import os
from pathlib import Path


def read_config(path):
    """Read a config file."""
    with open(path) as f:
        return f.read()


def process_input(user_input):
    """Process user input — vulnerable to injection."""
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query


class AuthService:
    def login(self, username, password):
        return self._validate(username, password)

    def _validate(self, username, password):
        query = f"SELECT * FROM users WHERE user='{username}'"
        return query

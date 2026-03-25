# Line numbers are critical for tests — do not add/remove lines without updating tests
import os
from html import escape


def vulnerable_sqli(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)

def sanitized_xss(user_input):
    safe = escape(user_input)
    return f"<div>{safe}</div>"

def conditional_sanitizer(user_input, flag):
    data = user_input
    if flag:
        data = escape(data)
    return f"<div>{data}</div>"

def hardcoded_no_source():
    query = "SELECT * FROM config WHERE key = 'version'"
    cursor.execute(query)

def multi_step_flow(request):
    raw = request.args.get("q")
    trimmed = raw.strip()
    query = "SELECT * FROM users WHERE name = '" + trimmed + "'"
    cursor.execute(query)

def calls_unknown(user_input):
    processed = external_lib.process(user_input)
    cursor.execute(processed)

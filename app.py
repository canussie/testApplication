import os
import sqlite3
import urllib.request
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse

app = FastAPI(title="Scanner Test Target Application")

# ==============================================================================
# CATEGORY 03: INJECTION PATTERNS
# ==============================================================================

@app.get("/search-user")
def search_user(username: str):
    # LINE 20: SQL Injection (Raw string concatenation into SQL query)
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


@app.get("/ping-host")
def ping_host(hostname: str):
    # LINE 29: Command Injection (Unsanitized system command execution)
    os.system(f"ping -c 1 {hostname}")
    return {"status": "executed"}


@app.get("/fetch-avatar")
def fetch_avatar(url: str):
    # LINE 36: Server-Side Request Forgery / SSRF (Arbitrary URL Fetching)
    response = urllib.request.urlopen(url)
    return {"data": response.read().decode('utf-8')}


@app.post("/load-config")
def load_config(yaml_data: str):
    # LINE 43: Insecure Deserialization (Unsafe YAML loading leading to RCE)
    data = yaml.load(yaml_data)  # pyyaml 5.1 vulnerable load
    return {"config": data}


@app.get("/read-log")
def read_log(filename: str):
    # LINE 50: Path Traversal / Arbitrary File Read
    file_path = os.path.join("/var/log/app/", filename)
    with open(file_path, "r") as f:
        return {"content": f.read()}

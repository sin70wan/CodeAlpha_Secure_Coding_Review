"""
VULNERABLE WEB APPLICATION - DO NOT USE IN PRODUCTION
This code contains security vulnerabilities for educational purposes
CodeAlpha Secure Coding Review - Task 3
"""

from flask import Flask, request, render_template_string, session, jsonify
import sqlite3
import hashlib
import pickle
import base64
import subprocess
import os
import re

app = Flask(__name__)
app.secret_key = "hardcoded_secret_key_12345"  # VULNERABILITY 1: Hardcoded secret

# VULNERABILITY 2: Hardcoded credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    ''')
    # Insert test user
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user')")
    conn.commit()
    conn.close()

# VULNERABILITY 3: SQL Injection
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Direct string concatenation - VULNERABLE TO SQL INJECTION!
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing query: {query}")  # VULNERABILITY 4: Logging sensitive data
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            session['role'] = user[3]
            return f"Welcome {username}! Your role is {user[3]}"
        else:
            return "Login failed!", 401
    except Exception as e:
        # VULNERABILITY 5: Information disclosure in error messages
        return f"Database error: {str(e)}", 500

# VULNERABILITY 6: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # Direct shell command with user input - EXTREMELY DANGEROUS!
    result = subprocess.check_output(f"ping -c 4 {host}", shell=True, stderr=subprocess.STDOUT)
    return f"<pre>{result.decode()}</pre>"

# VULNERABILITY 7: Insecure Deserialization
@app.route('/load_session')
def load_session():
    data = request.args.get('data', '')
    try:
        # Pickle can execute arbitrary code!
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        return f"Loaded: {obj}"
    except:
        return "Error loading data"

# VULNERABILITY 8: No Rate Limiting / Authentication
@app.route('/admin/delete_user')
def delete_user():
    user_id = request.args.get('id', '1')
    # No authentication check!
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")  # Also SQL injection!
    conn.commit()
    conn.close()
    return f"User {user_id} deleted!"

# VULNERABILITY 9: Weak Password Hashing
def hash_password(password):
    # Using MD5 - COMPLETELY INSECURE!
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY 10: Path Traversal
@app.route('/read_file')
def read_file():
    filename = request.args.get('file', '')
    # No path validation - can read ANY file!
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return content
    except:
        return "File not found"

# VULNERABILITY 11: Cross-Site Scripting (XSS)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # No output encoding - XSS vulnerability!
    return render_template_string(f"<h1>Search Results for: {query}</h1><p>No results found.</p>")

# VULNERABILITY 12: Insecure Direct Object Reference (IDOR)
@app.route('/user/profile')
def user_profile():
    user_id = request.args.get('user_id', '1')
    # Can access ANY user's profile without authorization
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT username, role FROM users WHERE id = {user_id}")
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({"username": user[0], "role": user[1]})
    return "User not found", 404

# VULNERABILITY 13: Missing Security Headers
@app.route('/')
def index():
    return '''
    <html>
        <body>
            <h1>Vulnerable App</h1>
            <form action="/login" method="post">
                Username: <input name="username"><br>
                Password: <input name="password" type="password"><br>
                <input type="submit">
            </form>
            <hr>
            <a href="/admin/delete_user?id=2">Delete User 2</a><br>
            <a href="/read_file?file=/etc/passwd">Read /etc/passwd</a><br>
            <a href="/ping?host=google.com">Ping Google</a><br>
            <a href="/search?q=<script>alert('XSS')</script>">XSS Test</a>
        </body>
    </html>
    '''

# VULNERABILITY 14: Information Exposure
@app.route('/debug')
def debug():
    # Exposes sensitive system information!
    return jsonify({
        "app_secret": app.secret_key,
        "python_version": os.sys.version,
        "environment": dict(os.environ),
        "database_path": os.path.abspath('users.db')
    })

# VULNERABILITY 15: Weak Session Management
@app.route('/logout')
def logout():
    # Session doesn't properly invalidate
    session.clear()  # This is actually okay, but lack of CSRF protection is bad
    return "Logged out"

if __name__ == '__main__':
    init_db()
    # Running in debug mode - VULNERABILITY 16
    app.run(host='0.0.0.0', port=5000, debug=True)
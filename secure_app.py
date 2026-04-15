"""
SECURE WEB APPLICATION
Following OWASP Top 10 and secure coding best practices
CodeAlpha Secure Coding Review - Task 3 - Remediated Version
"""

from flask import Flask, request, render_template_string, session, jsonify, abort, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlite3
import secrets
import re
import os
from datetime import datetime, timedelta
import bleach
from functools import wraps

app = Flask(__name__)

# SECURITY FIX 1: Use environment variable for secret key
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# SECURITY FIX 2: Add security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# SECURITY FIX 3: Rate limiting
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# SECURITY FIX 4: Use parameterized queries (No SQL injection)
def get_db():
    conn = sqlite3.connect('secure_users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_secure_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    ''')
    
    # Insert admin with secure password hashing
    admin_hash = generate_password_hash(os.environ.get('ADMIN_PASSWORD', secrets.token_urlsafe(16)))
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
    ''', ('admin', admin_hash, 'admin'))
    
    conn.commit()
    conn.close()

# SECURITY FIX 5: Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# SECURITY FIX 6: Role-based access control
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# SECURITY FIX 7: Secure login with account lockout
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Input validation
    if not username or not password:
        return "Username and password required", 400
    
    # Validate username format (allowlist)
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return "Invalid username format", 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # SECURITY FIX 8: Parameterized query
    cursor.execute('SELECT id, username, password_hash, role, login_attempts, locked_until FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if user:
        # Check if account is locked
        if user['locked_until'] and datetime.now() < datetime.fromisoformat(user['locked_until']):
            return "Account locked. Try again later.", 403
        
        # Verify password
        if check_password_hash(user['password_hash'], password):
            # Reset login attempts
            cursor.execute('UPDATE users SET login_attempts = 0, last_login = ? WHERE id = ?', 
                          (datetime.now().isoformat(), user['id']))
            conn.commit()
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            
            conn.close()
            return f"Welcome {user['username']}!"
        else:
            # Increment login attempts
            attempts = user['login_attempts'] + 1
            locked_until = None
            if attempts >= 5:
                locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
            
            cursor.execute('UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?',
                          (attempts, locked_until, user['id']))
            conn.commit()
            conn.close()
            return "Invalid credentials", 401
    else:
        conn.close()
        return "Invalid credentials", 401

# SECURITY FIX 9: Secure command execution
@app.route('/ping')
@limiter.limit("10 per minute")
def ping():
    host = request.args.get('host', '')
    
    # Validate hostname format (allowlist)
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        return "Invalid hostname", 400
    
    # SECURITY FIX 10: Use list form, not shell=True
    try:
        result = subprocess.run(['ping', '-c', '4', host], 
                               capture_output=True, 
                               timeout=10,
                               text=True)
        return f"<pre>{result.stdout if result.returncode == 0 else result.stderr}</pre>"
    except subprocess.TimeoutExpired:
        return "Command timed out", 408
    except Exception as e:
        # SECURITY FIX 11: Generic error message
        return "Unable to execute command", 500

# SECURITY FIX 12: No insecure deserialization - Use JSON only
@app.route('/api/data', methods=['POST'])
@login_required
def receive_data():
    data = request.get_json()
    if not data:
        return "Invalid JSON", 400
    # Validate data structure
    allowed_fields = {'name', 'email', 'age'}
    if not all(field in allowed_fields for field in data.keys()):
        return "Invalid fields", 400
    return jsonify({"status": "received", "data": data})

# SECURITY FIX 13: Admin endpoint with authentication and authorization
@app.route('/admin/delete_user')
@login_required
@admin_required
@limiter.limit("10 per hour")
def delete_user():
    user_id = request.args.get('id', '')
    
    if not user_id or not user_id.isdigit():
        return "Invalid user ID", 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Prevent self-deletion
    if int(user_id) == session['user_id']:
        conn.close()
        return "Cannot delete yourself", 403
    
    cursor.execute('DELETE FROM users WHERE id = ?', (int(user_id),))
    conn.commit()
    conn.close()
    
    return f"User {user_id} deleted successfully"

# SECURITY FIX 14: Secure file reading with path validation
@app.route('/read_file')
@login_required
def read_file():
    filename = request.args.get('file', '')
    
    # SECURITY FIX 15: Path validation
    if not filename or '..' in filename or filename.startswith('/'):
        return "Invalid filename", 400
    
    # Only allow specific directory
    allowed_dir = os.path.join(os.path.dirname(__file__), 'allowed_files')
    safe_path = os.path.normpath(os.path.join(allowed_dir, filename))
    
    if not safe_path.startswith(allowed_dir):
        return "Access denied", 403
    
    try:
        with open(safe_path, 'r') as f:
            # Limit file size
            content = f.read(1024 * 1024)  # Max 1MB
        return content
    except FileNotFoundError:
        return "File not found", 404

# SECURITY FIX 16: XSS prevention with output encoding
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Escape user input
    escaped_query = bleach.clean(query, strip=True)
    return render_template_string("""
        <h1>Search Results for: {{ query }}</h1>
        <p>No results found.</p>
    """, query=escaped_query)

# SECURITY FIX 17: Proper session logout
@app.route('/logout')
def logout():
    session.clear()
    # Create new session ID
    session.permanent = False
    return redirect(url_for('index'))

# SECURITY FIX 18: Remove debug endpoint and sensitive info exposure

# SECURITY FIX 19: Secure index page
@app.route('/')
def index():
    return '''
    <html>
        <head>
            <title>Secure Application</title>
        </head>
        <body>
            <h1>Secure Application</h1>
            <form action="/login" method="post">
                Username: <input name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit">
            </form>
            <hr>
            <a href="/search?q=test">Search</a>
        </body>
    </html>
    '''

if __name__ == '__main__':
    init_secure_db()
    # SECURITY FIX 20: Run securely
    app.run(host='127.0.0.1', port=5000, debug=False)
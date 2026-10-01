from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from functools import wraps
from cryptography.fernet import Fernet
import os, sqlite3, datetime, re, hashlib
from werkzeug.utils import secure_filename
import pdfplumber
import pytz
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# ==================== TIMEZONE SETUP (ADD THIS BLOCK HERE) ====================
# Set Indian Standard Time (IST)
IST = pytz.timezone('Asia/Kolkata')

def get_ist_time():
    """Returns current IST time as formatted string"""
    from datetime import datetime
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")

# ==================== CONFIGURATION ====================
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Encryption
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, "rb") as f:
    cipher = Fernet(f.read())

# ==================== DATABASE ====================
def get_db():
    return sqlite3.connect("security_logs.db", timeout=30)

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Check if data exists
    c.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'")
    if c.fetchone()[0] > 0:
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] > 0:
            print("✅ Database already exists")
            conn.close()
            return
    
    print("📦 Creating database...")
    
    # Users table
    c.execute('''CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT, email TEXT, role TEXT DEFAULT 'user',
        is_approved INTEGER DEFAULT 0, is_blocked INTEGER DEFAULT 0, registered_date TEXT)''')
    
    # Documents table
    c.execute('''CREATE TABLE documents(id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT, uploaded_by TEXT, upload_time TEXT, is_public INTEGER DEFAULT 0,
        doi TEXT, journal TEXT, authors TEXT, publication_year INTEGER, abstract TEXT)''')
    
    # Access control
    c.execute('''CREATE TABLE document_access(id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER, username TEXT)''')
    
    # Logs & Security
    c.execute('''CREATE TABLE audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, action TEXT, time TEXT)''')
    c.execute('''CREATE TABLE blocked_ips(ip TEXT PRIMARY KEY)''')
    c.execute('''CREATE TABLE blocked_users(username TEXT PRIMARY KEY)''')
    c.execute('''CREATE TABLE failed_attempts(ip TEXT PRIMARY KEY, attempts INTEGER)''')
    
    # Requests
    c.execute('''CREATE TABLE access_requests(id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, document_id INTEGER, status TEXT DEFAULT 'pending', requested_time TEXT)''')
    
    # User Features
    c.execute('''CREATE TABLE annotations(id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER, username TEXT, annotation_text TEXT, page_number INTEGER,
        highlight_text TEXT, category TEXT, created_time TEXT)''')
    
    # Create admin
    c.execute("INSERT INTO users(username, password, role, is_approved) VALUES('admin', 'admin123', 'admin', 1)")
    
    conn.commit()
    conn.close()
    print("✅ Database ready")

init_db()

# ==================== HELPER FUNCTIONS ====================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session or session.get("role") != "admin":
            return "Access Denied", 403
        return f(*args, **kwargs)
    return decorated

def log_action(username, action):
    try:
        conn = get_db()
        conn = get_db()
        IST = pytz.timezone('Asia/Kolkata')
        current_time = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        conn.cursor().execute("INSERT INTO audit_logs(username, action, time) VALUES(?,?,?)",
                              (username, action, current_time))
        conn.commit()
        conn.close()
        print(f"✅ Logged: {username} - {action}")  # Debug print
    except Exception as e:
        print(f"❌ Logging failed: {e}")  # Debug print

# ==================== AUTHENTICATION ====================
@app.route("/")
def home():
    return render_template("welcome.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users(username, password, email, registered_date) VALUES(?,?,?,?)",
                      (request.form['username'], request.form['password'], request.form.get('email', ''),
                       datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            flash("Registration successful! Wait for admin approval.", "success")
            return redirect(url_for("login"))
        except:
            flash("Username already exists", "danger")
        finally:
            conn.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    role_param = request.args.get("role", "user")
    
    if request.method == "POST":
        username, password, role = request.form['username'], request.form['password'], request.form['role']
        ip = request.remote_addr
        
        conn = get_db()
        c = conn.cursor()
        
        if role == "admin":
            user = c.execute("SELECT * FROM users WHERE username=? AND password=? AND role='admin'", (username, password)).fetchone()
        else:
            user = c.execute("SELECT * FROM users WHERE username=? AND password=? AND role='user' AND is_approved=1", (username, password)).fetchone()
        
        if user:
            session["user"], session["role"] = username, role
            log_action(username, f"Successful {role} login")  
            c.execute("DELETE FROM failed_attempts WHERE ip=?", (ip,))
            conn.commit()
            conn.close()
            return redirect(url_for("dashboard"))
        
        # Track failed attempts
        attempts = c.execute("SELECT attempts FROM failed_attempts WHERE ip=?", (ip,)).fetchone()
        attempts = (attempts[0] + 1) if attempts else 1
        c.execute("INSERT OR REPLACE INTO failed_attempts(ip, attempts) VALUES(?,?)", (ip, attempts))
        
        if attempts >= 3:
            c.execute("INSERT OR IGNORE INTO blocked_ips(ip) VALUES(?)", (ip,))
            c.execute("DELETE FROM failed_attempts WHERE ip=?", (ip,))
        
        conn.commit()
        conn.close()
        
        if attempts >= 3:
            return render_template("blocked.html")
        
        error = "Invalid credentials" if role == "admin" else "Invalid credentials or account not approved"
        return render_template("login.html", error=error, role=role_param)
    
    return render_template("login.html", role=role_param)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("admin_dashboard.html" if session["role"] == "admin" else "user_dashboard.html")

# ==================== USER FEATURES ====================
@app.route("/my_uploads")
@login_required
def my_uploads():
    if session["role"] != "user":
        return redirect(url_for("documents"))
    conn = get_db()
    docs = conn.cursor().execute("SELECT id, filename, upload_time, is_public FROM documents WHERE uploaded_by=? ORDER BY id DESC", (session["user"],)).fetchall()
    conn.close()
    return render_template("my_uploads.html", docs=docs)

@app.route("/upload_my_document", methods=["GET", "POST"])
@login_required
def upload_my_document():
    if session["role"] != "user":
        return redirect(url_for("documents"))
    
    if request.method == "POST":
        file = request.files.get("file")
        if file:
            filename = secure_filename(file.filename)
            with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as f:
                f.write(cipher.encrypt(file.read()))
            
            is_public = 1 if request.form.get("is_public") == "on" else 0
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO documents(filename, uploaded_by, upload_time, is_public) VALUES(?,?,?,?)",
                      (filename, session['user'], datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"), is_public))
            doc_id = c.lastrowid
            if not is_public:
                c.execute("INSERT INTO document_access(document_id, username) VALUES(?,?)", (doc_id, session['user']))
            conn.commit()
            log_action(session['user'], "Uploaded a document")  # Filename hidden
            conn.close()
            flash("Document uploaded!", "success")
    
    return render_template("upload_my_document.html")

@app.route("/download/<filename>")
@login_required
def download_file(filename):
    # Check if user owns this file
    conn = get_db()
    c = conn.cursor()
    doc = c.execute("SELECT * FROM documents WHERE filename=? AND uploaded_by=?", (filename, session["user"])).fetchone()
    conn.close()
    
    if not doc:
        return "Access Denied", 403
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(filepath, "rb") as f:
        decrypted = cipher.decrypt(f.read())
    
    return decrypted, 200, {
        "Content-Type": "application/pdf",
        "Content-Disposition": f"attachment; filename={filename}"
    }

@app.route("/share_document/<int:doc_id>", methods=["GET", "POST"])
@login_required
def share_document(doc_id):
    if session["role"] != "user":
        return redirect(url_for("documents"))
    
    conn = get_db()
    c = conn.cursor()
    doc = c.execute("SELECT filename FROM documents WHERE id=? AND uploaded_by=?", (doc_id, session["user"])).fetchone()
    
    if not doc:
        conn.close()
        return redirect(url_for("my_uploads"))
    
    if request.method == "POST":
        share_with = request.form.get("share_with")
        c.execute("INSERT OR IGNORE INTO document_access(document_id, username) VALUES(?,?)", (doc_id, share_with))
        conn.commit()
        log_action(session['user'], f"Shared a document with {share_with}")
        flash(f"Shared with {share_with}", "success")
    
    users = c.execute("SELECT username FROM users WHERE role='user' AND username != ?", (session["user"],)).fetchall()
    conn.close()
    return render_template("share_document.html", doc=doc, users=users)

@app.route("/documents")
@login_required
def documents():
    conn = get_db()
    c = conn.cursor()
    if session["role"] == "admin":
        # Admin sees ONLY documents uploaded by admin
        docs = c.execute("SELECT id, filename FROM documents WHERE uploaded_by='admin' ORDER BY id DESC").fetchall()
    else:
        # Users see their own uploads + public docs + shared docs
        docs = c.execute("""SELECT DISTINCT d.id, d.filename FROM documents d
            LEFT JOIN document_access da ON d.id = da.document_id 
            WHERE d.uploaded_by=? OR d.is_public=1 OR da.username=?
            ORDER BY d.id DESC""", (session["user"], session["user"])).fetchall()
    conn.close()
    return render_template("documents.html", docs=docs)

@app.route("/view/<filename>")
@login_required
def view_file(filename):
    conn = get_db()
    c = conn.cursor()
    
    if session["role"] != "admin":
        access = c.execute("""SELECT * FROM documents d
            LEFT JOIN document_access da ON d.id = da.document_id 
            WHERE d.filename=? AND (d.uploaded_by=? OR d.is_public=1 OR da.username=?)""",
            (filename, session["user"], session["user"])).fetchone()
        if not access:
            conn.close()
            return "Access Denied"
    conn.close()
    
    log_action(session["user"], "Viewed a document")  # Filename hidden
    with open(os.path.join(UPLOAD_FOLDER, filename), "rb") as f:
        return cipher.decrypt(f.read()), 200, {"Content-Type": "application/pdf"}

# ==================== CITATIONS (Auto-citation) ====================
def generate_citation(doc, style='apa'):
    authors, year, title, journal, doi = doc[3] or 'Unknown', doc[4] or 'n.d.', doc[0].replace('.pdf', ''), doc[2] or '', doc[1] or ''
    if style == 'apa':
        return f"{authors} ({year}). {title}. {journal}. {f'https://doi.org/{doi}' if doi else ''}"
    elif style == 'bibtex':
        return f"@article{{{hashlib.md5(title.encode()).hexdigest()[:8]},\n    author = {{{authors}}},\n    title = {{{title}}},\n    year = {{{year}}},\n    doi = {{{doi}}}}}"
    return f"{authors}. \"{title}.\" {journal}, {year}."

@app.route("/get_citation/<int:doc_id>/<style>")
@login_required
def get_citation(doc_id, style):
    conn = get_db()
    doc = conn.cursor().execute("SELECT filename, doi, journal, authors, publication_year FROM documents WHERE id=?", (doc_id,)).fetchone()
    conn.close()
    return jsonify({'citation': generate_citation(doc, style)}) if doc else jsonify({'error': 'Not found'}), 404

@app.route("/export_bibtex/<int:doc_id>")
@login_required
def export_bibtex(doc_id):
    conn = get_db()
    c = conn.cursor()
    doc = c.execute("SELECT filename, doi, journal, authors, publication_year FROM documents WHERE id=?", (doc_id,)).fetchone()
    conn.close()
    
    if not doc:
        flash("Document not found", "danger")
        return redirect(url_for("documents"))
    
    authors = doc[3] or 'Unknown'
    year = doc[4] or 'n.d.'
    title = doc[0].replace('.pdf', '')
    journal = doc[2] or ''
    doi = doc[1] or ''
    
    citation_id = hashlib.md5(title.encode()).hexdigest()[:8]
    
    bibtex = f"""@article{{{citation_id},
    author = {{{authors}}},
    title = {{{title}}},
    journal = {{{journal}}},
    year = {{{year}}},
    doi = {{{doi}}}
}}"""
    
    response = app.make_response(bibtex)
    response.mimetype = 'text/plain'
    response.headers['Content-Disposition'] = f'attachment; filename={title}.bib'
    return response

# ==================== ANNOTATIONS ====================
@app.route("/add_annotation", methods=["POST"])
@login_required
def add_annotation():
    data = request.json
    conn = get_db()
    conn.cursor().execute("""INSERT INTO annotations(document_id, username, annotation_text, page_number, highlight_text, category, created_time)
        VALUES(?,?,?,?,?,?,?)""", (data['document_id'], session['user'], data['annotation_text'], data.get('page_number', 1),
        data.get('highlight_text', ''), data.get('category', 'general'), datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route("/search_annotations")
@login_required
def search_annotations():
    query = request.args.get('q', '')
    if len(query) < 3:
        return jsonify([])
    conn = get_db()
    results = conn.cursor().execute("""SELECT a.annotation_text, a.highlight_text, a.created_time, d.filename, d.id
        FROM annotations a JOIN documents d ON a.document_id = d.id
        WHERE a.username=? AND (a.annotation_text LIKE ? OR a.highlight_text LIKE ?)
        ORDER BY a.created_time DESC LIMIT 50""", (session['user'], f'%{query}%', f'%{query}%')).fetchall()
    conn.close()
    return jsonify([{'annotation_text': r[0], 'highlight_text': r[1], 'created_time': r[2], 'document_name': r[3], 'document_id': r[4]} for r in results])

# ==================== REQUEST ACCESS ====================
@app.route("/all_documents")
@login_required
def all_documents():
    if session["role"] != "user":
        return redirect(url_for("documents"))
    conn = get_db()
    c = conn.cursor()
    all_docs = c.execute("SELECT id, filename, uploaded_by FROM documents WHERE is_public=0").fetchall()
    accessible = {row[0] for row in c.execute("SELECT document_id FROM document_access WHERE username=?", (session["user"],))}
    requested = {row[0] for row in c.execute("SELECT document_id FROM access_requests WHERE username=? AND status='pending'", (session["user"],))}
    conn.close()
    return render_template("all_documents.html", all_docs=all_docs, accessible_ids=accessible, requested_ids=requested)

@app.route("/request_access/<int:doc_id>")
@login_required
def request_access(doc_id):
    if session["role"] != "user":
        return redirect(url_for("documents"))
    conn = get_db()
    c = conn.cursor()
    if not c.execute("SELECT * FROM access_requests WHERE username=? AND document_id=? AND status='pending'", (session["user"], doc_id)).fetchone():
        c.execute("INSERT INTO access_requests(username, document_id, requested_time) VALUES(?,?,?)",
                  (session["user"], doc_id, datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")))
        log_action(session['user'], f"Requested access to document {doc_id}")
        flash("Request sent to admin!", "success")
    conn.commit()
    conn.close()
    return redirect(url_for("all_documents"))

# ==================== ADMIN FUNCTIONS ====================
@app.route("/pending_users")
@admin_required
def pending_users():
    conn = get_db()
    users = conn.cursor().execute("SELECT id, username, email, registered_date FROM users WHERE role='user' AND is_approved=0").fetchall()
    conn.close()
    return render_template("pending_users.html", users=users)

@app.route("/approve_user/<int:user_id>")
@admin_required
def approve_user(user_id):
    conn = get_db()
    conn.cursor().execute("UPDATE users SET is_approved=1 WHERE id=?", (user_id,))
    conn.commit()
    log_action(session['user'], f"Approved user ID {user_id}")
    conn.close()
    flash("User approved!", "success")
    return redirect(url_for("pending_users"))

@app.route("/reject_user/<int:user_id>")
@admin_required
def reject_user(user_id):
    conn = get_db()
    conn.cursor().execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    log_action(session['user'], f"Rejected user ID {user_id}")
    conn.close()
    flash("User rejected", "warning")
    return redirect(url_for("pending_users"))

@app.route("/registered_users")
@admin_required
def registered_users():
    conn = get_db()
    users = conn.cursor().execute("SELECT id, username, email, registered_date, is_approved FROM users WHERE role='user' ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("registered_users.html", users=users)

@app.route("/create_user", methods=["GET", "POST"])
@admin_required
def create_user():
    if request.method == "POST":
        conn = get_db()
        try:
            conn.cursor().execute("INSERT INTO users(username, password, role, is_approved) VALUES(?,?,?,?)",
                                  (request.form['username'], request.form['password'], "user", 1))
            conn.commit()
            flash("User created", "success")
        except:
            flash("User exists", "danger")
        conn.close()
    conn = get_db()
    users = conn.cursor().execute("SELECT username FROM users WHERE role='user'").fetchall()
    conn.close()
    return render_template("create_user.html", users=users)

@app.route("/delete_user/<username>")
@admin_required
def delete_user(username):
    conn = get_db()
    c = conn.cursor()
    for table in ['users', 'document_access', 'blocked_users', 'access_requests', 'annotations']:
        c.execute(f"DELETE FROM {table} WHERE username=?", (username,))
    conn.commit()
    log_action(session['user'], f"Deleted user {username}")
    conn.close()
    flash(f"User {username} deleted", "success")
    return redirect(url_for("create_user"))

@app.route("/upload", methods=["GET", "POST"])
@admin_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if file:
            filename = secure_filename(file.filename)
            with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as f:
                f.write(cipher.encrypt(file.read()))
            
            conn = get_db()
            c = conn.cursor()
            c.execute("INSERT INTO documents(filename, uploaded_by, upload_time) VALUES(?,?,?)",
                      (filename, session['user'], datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")))
            doc_id = c.lastrowid
            for user in request.form.getlist("allowed_users"):
                c.execute("INSERT INTO document_access(document_id, username) VALUES(?,?)", (doc_id, user))
            conn.commit()
            log_action(session['user'], f"Uploaded file: {filename}")
            conn.close()
            flash("Document uploaded!", "success")
    
    conn = get_db()
    users = conn.cursor().execute("SELECT username FROM users WHERE role='user'").fetchall()
    conn.close()
    return render_template("upload.html", users=users)

@app.route("/blocked_management")
@admin_required
def blocked_management():
    conn = get_db()
    c = conn.cursor()
    blocked_ips = c.execute("SELECT ip FROM blocked_ips").fetchall()
    blocked_users = c.execute("SELECT username FROM blocked_users").fetchall()
    conn.close()
    return render_template("blocked_management.html", blocked_ips=blocked_ips, blocked_users=blocked_users)

@app.route("/unblock/<type>/<value>")
@admin_required
def unblock(type, value):
    conn = get_db()
    conn.cursor().execute(f"DELETE FROM blocked_{type}s WHERE {'ip' if type=='ip' else 'username'}=?", (value,))
    conn.commit()
    conn.close()
    return redirect(url_for("blocked_management"))

@app.route("/admin_stats")
@admin_required
def admin_stats():
    conn = get_db()
    c = conn.cursor()
    stats = {
        'users': c.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0],
        'pending': c.execute("SELECT COUNT(*) FROM users WHERE role='user' AND is_approved=0").fetchone()[0],
        'documents': c.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
        'audits': c.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    }
    conn.close()
    return render_template("stats.html", **stats)

@app.route("/admin_stats_data")
@admin_required
def admin_stats_data():
    conn = get_db()
    c = conn.cursor()
    
    # Total login attempts (all logs with "Failed Login" or "Viewed" etc. - count all logs)
    total_attempts = c.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    
    # Successful logins (count successful logins from logs - you need to track this)
    # For now, count distinct users who have logs
    successful_logins = c.execute("SELECT COUNT(DISTINCT username) FROM audit_logs").fetchone()[0]
    
    # Blocked IPs
    blocked_ips = c.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    
    # Blocked Users
    blocked_users = c.execute("SELECT COUNT(*) FROM blocked_users").fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'total_attempts': total_attempts,
        'successful_logins': successful_logins,
        'blocked_ips': blocked_ips,
        'blocked_users': blocked_users
    })

@app.route("/logs")
@admin_required
def view_logs():
    conn = get_db()
    c = conn.cursor()
    
    # Get logs from database
    raw_logs = c.execute("SELECT username, action, time FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall()
    
    # Convert to format expected by logs.html
    logs = []
    for log in raw_logs:
        # Determine threat level based on action
        threat = 'low'
        if 'Failed' in log[1] or 'failed' in log[1]:
            threat = 'high'
        elif 'Delete' in log[1] or 'delete' in log[1] or 'block' in log[1]:
            threat = 'medium'
        elif 'View' in log[1] or 'view' in log[1]:
            threat = 'low'
        
        logs.append({
            'ip': log[0],           # Username will show as IP (or change to actual IP if you have it)
            'time': log[2],         # Timestamp
            'status': 'completed',  # Default status
            'endpoint': log[1],     # Action performed
            'threat': threat        # Calculated threat level
        })
    
    conn.close()
    return render_template("logs.html", logs=logs)

@app.route("/access_requests")
@admin_required
def view_access_requests():
    conn = get_db()
    requests = conn.cursor().execute("""SELECT ar.id, ar.username, d.filename, ar.requested_time 
        FROM access_requests ar JOIN documents d ON ar.document_id = d.id WHERE ar.status='pending'""").fetchall()
    conn.close()
    return render_template("access_requests.html", requests=requests)

@app.route("/handle_request/<int:req_id>/<action>")
@admin_required
def handle_request(req_id, action):
    conn = get_db()
    c = conn.cursor()
    row = c.execute("SELECT username, document_id FROM access_requests WHERE id=?", (req_id,)).fetchone()
    if row:
        if action == "approve":
            c.execute("INSERT OR IGNORE INTO document_access(document_id, username) VALUES(?,?)", (row[1], row[0]))
        c.execute("UPDATE access_requests SET status=? WHERE id=?", (action, req_id))
        conn.commit()
    conn.close()
    return redirect(url_for("view_access_requests"))

# ==================== CONTEXT PROCESSOR ====================
@app.context_processor
def inject_counts():
    if session.get("role") == "admin":
        conn = get_db()
        c = conn.cursor()
        counts = {'pending_users': c.execute("SELECT COUNT(*) FROM users WHERE role='user' AND is_approved=0").fetchone()[0],
                  'pending_requests': c.execute("SELECT COUNT(*) FROM access_requests WHERE status='pending'").fetchone()[0]}
        conn.close()
        return counts
    return {'pending_users': 0, 'pending_requests': 0}

# ==================== RUN ====================
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)

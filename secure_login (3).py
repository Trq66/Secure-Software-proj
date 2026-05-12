import os
import sqlite3
import secrets
import io
from flask import Flask, render_template_string, request, session, redirect, url_for, abort, Response
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
DB_PATH = "secure_sis_demo.sqlite3"

# --- UI Styles & Templates ---
BASE_STYLE = """
<style>
    :root { 
        --primary: #1a365d; --secondary: #2c5282; --text: #2d3748; 
        --error: #e53e3e; --success: #38a169; --admin-gold: #d69e2e;
    }
    body { font-family: 'Segoe UI', sans-serif; background: #f7fafc; margin: 0; color: var(--text); }
    .navbar { background: var(--primary); color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
    .container { max-width: 900px; margin: 40px auto; background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
    table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
    th { background: #edf2f7; color: var(--secondary); font-size: 0.8rem; text-transform: uppercase; }
    .btn { padding: 8px 16px; border-radius: 6px; cursor: pointer; border: none; font-weight: bold; text-decoration: none; display: inline-block; font-size: 0.9rem; }
    .btn-save { background: var(--success); color: white; }
    .btn-delete { background: var(--error); color: white; }
    .admin-tools { border: 2px dashed var(--admin-gold); padding: 1.5rem; margin-top: 2rem; border-radius: 8px; background: #fffaf0; }
    .footer { text-align: center; margin-top: 50px; padding: 20px; font-size: 0.8rem; color: #718096; border-top: 1px solid #e2e8f0; }
</style>
"""

LOGIN_HTML = BASE_STYLE + """
<div class="container" style="max-width:400px; margin-top:100px; border-top: 6px solid var(--primary);">
    <h2 style="text-align:center;">Secure SIS Login</h2>
    {% if error %}<div style="color:var(--error); margin-bottom:15px;">{{ error }}</div>{% endif %}
    <form method="POST">
        <label>Email</label><br>
        <input name="email" type="email" style="width:100%; padding:10px; margin:8px 0 20px 0; border:1px solid #ccc; border-radius:4px;" required><br>
        <label>Password</label><br>
        <input name="password" type="password" style="width:100%; padding:10px; margin:8px 0 20px 0; border:1px solid #ccc; border-radius:4px;" required><br>
        <button type="submit" class="btn" style="width:100%; background:var(--primary); color:white;">Sign In</button>
    </form>
</div>
"""

DASHBOARD_HTML = BASE_STYLE + """
<div class="navbar">
    <strong>Secure SIS Portal</strong>
    <a href="/logout" style="color:white; text-decoration:none; font-weight:bold;">Logout</a>
</div>

<div class="container">
    <h2>Welcome Back, {{ role|capitalize }} ({{ email }})</h2>

    {% if role == 'student' %}
        <h3>My Grades</h3>
        <table>
            <tr><th>Subject</th><th>Grade</th></tr>
            {% for g in data %}
            <tr><td>{{ g.subject }}</td><td><strong>{{ g.grade }}%</strong></td></tr>
            {% endfor %}
        </table>
    {% else %}
        <h3>Grade Management</h3>
        <table>
            <tr><th>Student</th><th>Subject</th><th>Grade</th><th>Actions</th></tr>
            {% for g in data %}
            <tr>
                <form method="POST" action="/update">
                    <input type="hidden" name="id" value="{{ g.id }}">
                    <td>{{ g.student_email }}</td>
                    <td>{{ g.subject }}</td>
                    <td><input type="number" name="grade" value="{{ g.grade }}" style="width:50px;">%</td>
                    <td>
                        <button type="submit" class="btn btn-save">Update</button>
                        {% if role == 'admin' %}
                        <a href="/delete/{{ g.id }}" class="btn btn-delete" style="font-size:0.7rem;">Delete</a>
                        {% endif %}
                    </td>
                </form>
            </tr>
            {% endfor %}
        </table>
    {% endif %}

    {% if role == 'admin' %}
    <div class="admin-tools">
        <h4 style="color:var(--admin-gold); margin:0 0 10px 0;">Admin Privilege Zone</h4>
        <p style="font-size:0.85rem;">Authorized Personnel Only: Generate a text-based audit trail of all student records.</p>
        <a href="/admin/download_logs" class="btn" style="background:var(--admin-gold); color:white;">Download System Audit Log</a>
    </div>
    {% endif %}
</div>

<div class="footer">
    Developed by <strong>Muneer Elmoussa & Tariq Hussein</strong> | SQL Database Protected
</div>
"""

# --- Backend Logic ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password_hash TEXT, role TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS grades (id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER, subject TEXT, grade INTEGER)")
        
        if not conn.execute("SELECT 1 FROM users").fetchone():
            users = [
                ("student@example.com", generate_password_hash("Student123!"), "student"),
                ("instructor@example.com", generate_password_hash("Instructor123!"), "instructor"),
                ("admin@example.com", generate_password_hash("Admin123!"), "admin")
            ]
            conn.executemany("INSERT INTO users (email, password_hash, role) VALUES (?,?,?)", users)
            conn.execute("INSERT INTO grades (student_id, subject, grade) VALUES (1, 'Network Security', 85)")
            conn.execute("INSERT INTO grades (student_id, subject, grade) VALUES (1, 'SQL Management', 92)")
            conn.commit()

app = Flask(__name__)
app.secret_key = "super_secure_key"

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email").lower().strip()
        password = request.form.get("password")
        
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.update({"uid": user["id"], "role": user["role"], "email": user["email"]})
                return redirect(url_for("dashboard"))
            
        return render_template_string(LOGIN_HTML, error="Invalid email or password")
    return render_template_string(LOGIN_HTML, error=None)

@app.route("/dashboard")
def dashboard():
    if "uid" not in session: return redirect(url_for("login"))
    with get_db() as conn:
        if session["role"] == "student":
            data = conn.execute("SELECT * FROM grades WHERE student_id = ?", (session["uid"],)).fetchall()
        else:
            data = conn.execute("SELECT g.*, u.email as student_email FROM grades g JOIN users u ON g.student_id = u.id").fetchall()
    return render_template_string(DASHBOARD_HTML, role=session["role"], email=session["email"], data=data)

@app.route("/update", methods=["POST"])
def update_grade():
    if session.get("role") not in ["instructor", "admin"]: abort(403)
    with get_db() as conn:
        conn.execute("UPDATE grades SET grade = ? WHERE id = ?", (request.form.get("grade"), request.form.get("id")))
        conn.commit()
    return redirect(url_for("dashboard"))

@app.route("/delete/<int:gid>")
def delete_grade(gid):
    if session.get("role") != "admin": abort(403)
    with get_db() as conn:
        conn.execute("DELETE FROM grades WHERE id = ?", (gid,))
        conn.commit()
    return redirect(url_for("dashboard"))

@app.route("/admin/download_logs")
def download_logs():
    if session.get("role") != "admin": abort(403)
    
    # Generate a simple text log from the database
    output = io.StringIO()
    output.write(f"SECURE SIS SYSTEM AUDIT LOG\n")
    output.write(f"Authorized Admin: {session['email']}\n")
    output.write("-" * 30 + "\n\n")
    
    with get_db() as conn:
        data = conn.execute("SELECT u.email, g.subject, g.grade FROM grades g JOIN users u ON g.student_id = u.id").fetchall()
        for row in data:
            output.write(f"STUDENT: {row['email']} | SUBJECT: {row['subject']} | GRADE: {row['grade']}%\n")
    
    return Response(
        output.getvalue(),
        mimetype="text/plain",
        headers={"Content-disposition": "attachment; filename=sis_audit_log.txt"}
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=False, port=5001)
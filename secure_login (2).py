"""
Secure login process for the Online Secure Student Information System.

Security features:
- Server-side input validation
- Parameterized SQL query to prevent SQL injection
- Salted password hashing using Werkzeug
- Generic authentication errors to prevent account enumeration
- Simple login rate limiting
- CSRF token validation
- Secure session configuration

Run locally:
    pip install Flask Werkzeug
    python secure_login.py
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secure_sis_demo.sqlite3"
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
MAX_EMAIL_LENGTH = 254
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60


@dataclass
class LoginAttempt:
    count: int
    locked_until: float

FAILED_ATTEMPTS: dict[str, LoginAttempt] = {}


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
        PERMANENT_SESSION_LIFETIME=1800,
    )

    @app.get("/")
    def index():
        if "user_id" in session:
            return f"Logged in as user #{session['user_id']} with role {session['role']}"
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
            return render_template_string(LOGIN_TEMPLATE, csrf_token=token, error=None)

        csrf_token = request.form.get("csrf_token", "")
        if not csrf_token or not secrets.compare_digest(csrf_token, session.get("csrf_token", "")):
            abort(403)

        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        client_key = rate_limit_key(request.remote_addr or "unknown", email)

        if is_locked(client_key):
            return render_template_string(
                LOGIN_TEMPLATE,
                csrf_token=session["csrf_token"],
                error="Too many failed attempts. Please try again later.",
            ), 429

        if not is_valid_email(email) or not is_valid_password_shape(password):
            record_failed_attempt(client_key)
            return login_failed_response()

        user = find_user_by_email(email)
        if user is None or not check_password_hash(user["password_hash"], password):
            record_failed_attempt(client_key)
            return login_failed_response()

        reset_failed_attempts(client_key)
        session.clear() 
        session.permanent = True
        session["user_id"] = user["id"]
        session["email"] = user["email"]
        session["role"] = user["role"]
        return redirect(url_for("index"))

    return app


def normalize_email(value: str) -> str:
    return value.strip().lower()


def is_valid_email(email: str) -> bool:
    return 1 <= len(email) <= MAX_EMAIL_LENGTH and EMAIL_PATTERN.fullmatch(email) is not None


def is_valid_password_shape(password: str) -> bool:
    return MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH


def rate_limit_key(ip_address: str, email: str) -> str:
    return f"{ip_address}:{email or 'unknown'}"


def is_locked(key: str) -> bool:
    attempt = FAILED_ATTEMPTS.get(key)
    return bool(attempt and attempt.locked_until > time.time())


def record_failed_attempt(key: str) -> None:
    attempt = FAILED_ATTEMPTS.get(key, LoginAttempt(count=0, locked_until=0))
    attempt.count += 1
    if attempt.count >= MAX_FAILED_ATTEMPTS:
        attempt.locked_until = time.time() + LOCKOUT_SECONDS
    FAILED_ATTEMPTS[key] = attempt


def reset_failed_attempts(key: str) -> None:
    FAILED_ATTEMPTS.pop(key, None)


def login_failed_response():
    return render_template_string(
        LOGIN_TEMPLATE,
        csrf_token=session.get("csrf_token", ""),
        error="Invalid email or password.",
    ), 401


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def find_user_by_email(email: str) -> Optional[sqlite3.Row]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT id, email, password_hash, role FROM users WHERE email = ? AND active = 1",
            (email,),
        ).fetchone()


def initialize_demo_database() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('student', 'instructor', 'admin')),
                active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        demo_email = "student@example.com"
        exists = conn.execute("SELECT 1 FROM users WHERE email = ?", (demo_email,)).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                (demo_email, generate_password_hash("Student123!"), "student"),
            )


LOGIN_TEMPLATE = """
<!doctype html>
<title>Secure SIS Login</title>
<h1>Secure SIS Login</h1>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post" action="/login" autocomplete="off">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <label>Email <input name="email" type="email" maxlength="254" required></label><br>
  <label>Password <input name="password" type="password" minlength="8" maxlength="128" required></label><br>
  <button type="submit">Log in</button>
</form>
<p>Demo account: student@example.com / Student123!</p>
"""


if __name__ == "__main__":
    initialize_demo_database()
    create_app().run(debug=False)

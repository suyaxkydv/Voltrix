import os;
import re;
import sqlite3;
from datetime import datetime, timezone;
from functools import wraps;

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "voltrix.db")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
    SESSION_TYPE="filesystem",                       # server-side session
    SESSION_FILE_DIR=os.path.join(BASE, "flask_session"),
    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
);
Session(app);
socketio = SocketIO(app, manage_session=False, async_mode="threading");


# ---------- database ----------
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                receiver_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender_id, receiver_id);
            """
        )


def now():
    return datetime.now(timezone.utc).isoformat()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return jsonify(error="Not authenticated"), 401
        return f(*a, **kw)
    return wrapper


# ---------- pages ----------
@app.route("/")
def index():
    return redirect(url_for("chat_page" if "user_id" in session else "login_page"))


@app.route("/login")
def login_page():
    if "user_id" in session:
        return redirect(url_for("chat_page"))
    return render_template("login.html")


@app.route("/signup")
def signup_page():
    if "user_id" in session:
        return redirect(url_for("chat_page"))
    return render_template("signup.html")


@app.route("/chat")
def chat_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    return render_template("chat.html")


# ---------- auth API ----------
@app.post("/api/signup")
def api_signup():
    d = request.get_json(silent=True) or {}
    username = str(d.get("username", "")).strip()
    email = str(d.get("email", "")).strip()
    password = str(d.get("password", ""))
    confirm = str(d.get("confirmPassword", ""))

    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
        return jsonify(success=False, message="Username: 3-20 letters, numbers or _"), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify(success=False, message="Enter a valid email"), 400
    if len(password) < 6:
        return jsonify(success=False, message="Password must be at least 6 characters"), 400
    if password != confirm:
        return jsonify(success=False, message="Passwords do not match"), 400

    try:
        with db() as con:
            cur = con.execute(
                "INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                (username, email, generate_password_hash(password), now()),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(success=False, message="Username already taken"), 409

    session.clear()
    session["user_id"], session["username"] = uid, username
    socketio.emit("users_changed")
    return jsonify(success=True)


@app.post("/api/login")
def api_login():
    d = request.get_json(silent=True) or {}
    with db() as con:
        u = con.execute("SELECT * FROM users WHERE username=?", (str(d.get("username", "")),)).fetchone()
    if not u or not check_password_hash(u["password_hash"], str(d.get("password", ""))):
        return jsonify(success=False, message="Invalid username or password"), 401
    session.clear()
    session["user_id"], session["username"] = u["id"], u["username"]
    return jsonify(success=True)


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(success=True)


@app.get("/api/me")
@login_required
def api_me():
    return jsonify(id=session["user_id"], username=session["username"])


# ---------- chat API ----------
@app.get("/api/users")
@login_required
def api_users():
    with db() as con:
        rows = con.execute(
            "SELECT id, username FROM users WHERE id != ? ORDER BY username", (session["user_id"],)
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/api/messages/<int:other>")
@login_required
def api_messages(other):
    me = session["user_id"]
    with db() as con:
        rows = con.execute(
            """SELECT * FROM (
                 SELECT * FROM messages
                 WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
                 ORDER BY id DESC LIMIT 200
               ) ORDER BY id""",
            (me, other, other, me),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------- real-time (Socket.IO) ----------
online = {}  # user_id -> number of open connections


def broadcast_presence():
    socketio.emit("presence", list(online.keys()))


@socketio.on("connect")
def on_connect():
    if "user_id" not in session:
        return False  # reject unauthenticated sockets
    uid = session["user_id"]
    join_room(f"user:{uid}")
    online[uid] = online.get(uid, 0) + 1
    broadcast_presence()


@socketio.on("disconnect")
def on_disconnect():
    uid = session.get("user_id")
    if uid is None:
        return
    online[uid] = online.get(uid, 1) - 1
    if online[uid] <= 0:
        online.pop(uid, None)
    broadcast_presence()


@socketio.on("message")
def on_message(data):
    me = session.get("user_id")  # sender always comes from the session, never the client
    if me is None:
        return {"error": "Not authenticated"}
    try:
        to = int(data.get("to"))
    except (TypeError, ValueError, AttributeError):
        return {"error": "Invalid recipient"}
    body = str(data.get("body", "")).strip()[:2000]
    if not body or to == me:
        return {"error": "Invalid message"}

    with db() as con:
        if not con.execute("SELECT 1 FROM users WHERE id=?", (to,)).fetchone():
            return {"error": "User not found"}
        cur = con.execute(
            "INSERT INTO messages(sender_id,receiver_id,body,created_at) VALUES(?,?,?,?)",
            (me, to, body, now()),
        )
        msg = dict(con.execute("SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone())

    emit("message", msg, to=f"user:{me}")
    emit("message", msg, to=f"user:{to}")
    return {"ok": True}


@socketio.on("typing")
def on_typing(data):
    me = session.get("user_id")
    if me is None:
        return
    try:
        to = int(data.get("to"))
    except (TypeError, ValueError, AttributeError):
        return
    emit("typing", {"from": me}, to=f"user:{to}")


if __name__ == "__main__":
    init_db()
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)),
                 debug=True, allow_unsafe_werkzeug=True)

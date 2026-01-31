from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO, emit, disconnect
import sqlite3, bcrypt, random, secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
socketio = SocketIO(app)

# ---------- DATABASE ----------
def get_db():
    conn = sqlite3.connect("users.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

db = get_db()

# Users table
db.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password BLOB,
    color TEXT,
    role TEXT
)
""")

# Messages table
db.execute("""
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    content TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# Banned table
db.execute("""
CREATE TABLE IF NOT EXISTS banned (
    username TEXT UNIQUE
)
""")
db.commit()

# ---------- HELPERS ----------
def random_color():
    return "#{:06x}".format(random.randint(0, 0xFFFFFF))

# ---------- ROUTES ----------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].encode()

        banned = db.execute("SELECT * FROM banned WHERE username=?", (username,)).fetchone()
        if banned:
            return "You are banned."

        user = db.execute("SELECT username, password, role FROM users WHERE username=?", (username,)).fetchone()
        if user:
            if bcrypt.checkpw(password, user["password"]):
                session["user"] = user["username"]
                session["role"] = user["role"]
                return redirect("/chat")
            else:
                return "Incorrect password."
        else:
            return "User does not exist."

    return render_template("login.html")


@app.route("/signup", methods=["POST"])
def signup():
    username = request.form["username"].strip()
    password = request.form["password"].encode()
    pw_hash = bcrypt.hashpw(password, bcrypt.gensalt())
    color = random_color()
    role = "owner" if username.lower() == "cole" else "user"

    try:
        db.execute(
            "INSERT INTO users (username, password, color, role) VALUES (?, ?, ?, ?)",
            (username, pw_hash, color, role)
        )
        db.commit()
        session["user"] = username
        session["role"] = role
        return redirect("/chat")
    except sqlite3.IntegrityError:
        return "Username already exists."


@app.route("/chat")
def chat():
    if "user" not in session:
        return redirect("/")

    messages = db.execute("SELECT username, content FROM messages ORDER BY id ASC").fetchall()
    return render_template("chat.html", user=session["user"], role=session["role"], messages=messages)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------- OWNER CONTROLS ----------
@app.route("/ban", methods=["POST"])
def ban():
    if session.get("role") != "owner":
        return "Unauthorized"

    username = request.form["username"].strip()
    db.execute("INSERT OR IGNORE INTO banned VALUES (?)", (username,))
    db.commit()

    socketio.emit("system", f"{username} has been banned.", broadcast=True)
    return redirect("/chat")


@app.route("/rename", methods=["POST"])
def rename():
    if session.get("role") != "owner":
        return "Unauthorized"

    old = request.form["old"].strip()
    new = request.form["new"].strip()
    db.execute("UPDATE users SET username=? WHERE username=?", (new, old))
    db.execute("UPDATE messages SET username=? WHERE username=?", (new, old))
    db.commit()
    socketio.emit("system", f"{old} has been renamed to {new}.", broadcast=True)
    return redirect("/chat")


@app.route("/clear_chat", methods=["POST"])
def clear_chat():
    if session.get("role") != "owner":
        return "Unauthorized"

    db.execute("DELETE FROM messages")
    db.commit()
    socketio.emit("clear_chat", broadcast=True)
    socketio.emit("system", "Chat has been cleared by the owner.", broadcast=True)
    return redirect("/chat")


# ---------- SOCKET.IO ----------
@socketio.on("connect")
def connect():
    if "user" in session:
        # Kick banned users immediately
        banned = db.execute("SELECT * FROM banned WHERE username=?", (session["user"],)).fetchone()
        if banned:
            emit("system", "You have been banned.", room=request.sid)
            disconnect(request.sid)
            return

        emit("system", f"🟢 {session['user']} joined the chat", broadcast=True)


@socketio.on("disconnect")
def disconnect_user():
    if "user" in session:
        emit("system", f"🔴 {session['user']} left the chat", broadcast=True)


@socketio.on("message")
def message(text):
    if "user" not in session or text.strip() == "":
        return

    # Real-time ban check
    banned = db.execute("SELECT * FROM banned WHERE username=?", (session["user"],)).fetchone()
    if banned:
        emit("system", "You have been banned.", room=request.sid)
        disconnect(request.sid)
        return

    user = session["user"]
    color = db.execute("SELECT color FROM users WHERE username=?", (user,)).fetchone()["color"]

    db.execute("INSERT INTO messages (username, content) VALUES (?, ?)", (user, text))
    db.commit()

    emit("message", {"user": user, "text": text, "color": color}, broadcast=True)


if __name__ == "__main__":
    socketio.run(app, debug=True)

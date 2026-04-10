from flask import Flask, request, jsonify, session, render_template, redirect
import sqlite3
import bcrypt
import random
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"


# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password_hash BLOB,
        failed_attempts INTEGER DEFAULT 0,
        locked INTEGER DEFAULT 0
    )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------------- VALIDATION ----------------
def validate_input(username, email, password):
    if not username or len(username) < 3:
        return "Username must be at least 3 characters"

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return "Invalid email"

    if len(password) < 8:
        return "Password must be 8+ chars"

    if not re.search(r"[A-Z]", password):
        return "Need uppercase"

    if not re.search(r"[a-z]", password):
        return "Need lowercase"

    if not re.search(r"[0-9]", password):
        return "Need number"

    if not re.search(r"[!@#$%^&*]", password):
        return "Need special char"

    return None


# ---------------- REGISTER ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    error = validate_input(username, email, password)
    if error:
        return jsonify({"message": error})

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()

        cur.execute(
            "INSERT INTO users(username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hashed)
        )

        conn.commit()
        conn.close()

        return jsonify({"message": "Registered Successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username already exists"})


# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute(
        "SELECT password_hash, failed_attempts, locked FROM users WHERE username=?",
        (username,)
    )
    user = cur.fetchone()

    if not user:
        conn.close()
        return jsonify({"message": "User not found"})

    stored_hash, failed_attempts, locked = user

    if locked == 1:
        conn.close()
        return jsonify({"message": "Account locked"})

    if bcrypt.checkpw(password.encode(), stored_hash):
        cur.execute(
            "UPDATE users SET failed_attempts=0 WHERE username=?",
            (username,)
        )
        conn.commit()
        conn.close()

        otp = str(random.randint(1000, 9999))
        session["otp"] = otp
        session["temp_user"] = username

        return jsonify({
            "message": "OTP generated",
            "otp": otp
        })
    else:
        failed_attempts += 1

        if failed_attempts >= 3:
            cur.execute(
                "UPDATE users SET failed_attempts=?, locked=1 WHERE username=?",
                (failed_attempts, username)
            )
            conn.commit()
            conn.close()
            return jsonify({"message": "Account locked due to multiple attempts"})

        cur.execute(
            "UPDATE users SET failed_attempts=? WHERE username=?",
            (failed_attempts, username)
        )
        conn.commit()
        conn.close()

        return jsonify({"message": f"Invalid password ({failed_attempts}/3 attempts)"})


# ---------------- OTP VERIFY ----------------
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    user_otp = data.get("otp", "").strip()

    if "otp" not in session or "temp_user" not in session:
        return jsonify({"message": "Session expired"})

    if user_otp == session["otp"]:
        session["user"] = session["temp_user"]
        session.pop("otp", None)
        session.pop("temp_user", None)
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"message": "Invalid OTP"})


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html", user=session["user"])


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("index.html")


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
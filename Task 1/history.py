import sqlite3
import hashlib

DB_FILE = "passwords.db"


def create_table():
    """Create passwords table if it does not exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL UNIQUE
        )
    """)

    conn.commit()
    conn.close()


def hash_password(password):
    """Convert plain password into SHA-256 hash."""
    return hashlib.sha256(password.encode()).hexdigest()


def check_reuse(password):
    """Check whether the password hash already exists in database."""
    create_table()

    password_hash = hash_password(password)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM passwords WHERE password_hash = ?",
        (password_hash,)
    )

    result = cursor.fetchone()

    conn.close()

    return result is not None


def add_password(password):
    """Store password hash in database if not already present."""
    create_table()

    password_hash = hash_password(password)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO passwords (password_hash) VALUES (?)",
            (password_hash,)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


def view_all_hashes():
    """Return all stored password hashes from database."""
    create_table()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT id, password_hash FROM passwords")
    rows = cursor.fetchall()

    conn.close()

    return rows
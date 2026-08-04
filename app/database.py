import hashlib
import secrets
import sqlite3
from datetime import datetime

connection = sqlite3.connect("guardian.db", check_same_thread=False)
cursor = connection.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS attacks (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        website TEXT,

        attack_type TEXT,

        severity TEXT,

        source_ip TEXT,

        username TEXT,

        timestamp TEXT,

        status TEXT

    )
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT UNIQUE,

        email TEXT UNIQUE,

        website TEXT,

        password_hash TEXT,

        created_at TEXT,

        site_token TEXT

    )
""")

cursor.execute("PRAGMA table_info(users)")
columns = [row[1] for row in cursor.fetchall()]
if "site_token" not in columns:
    cursor.execute("ALTER TABLE users ADD COLUMN site_token TEXT")
    connection.commit()


def hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)

    digest = hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, _ = stored_hash.split("$", 1)
    except ValueError:
        return False

    return hash_password(password, salt) == stored_hash


def save_attack(
    website,
    attack_type,
    severity,
    source_ip,
    username,
    status="New"
):
    cursor.execute(
        """
        INSERT INTO attacks (
            website,
            attack_type,
            severity,
            source_ip,
            username,
            timestamp,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            website,
            attack_type,
            severity,
            source_ip,
            username,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            status
        )
    )

def generate_site_token() -> str:
    return secrets.token_urlsafe(24)


def create_user(username: str, email: str, website: str, password: str) -> bool:
    password_hash = hash_password(password)
    site_token = generate_site_token()

    cursor.execute(
        """
        INSERT INTO users (
            username,
            email,
            website,
            password_hash,
            created_at,
            site_token
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            email,
            website,
            password_hash,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            site_token
        )
    )
    connection.commit()
    return True


def get_user_by_username(username: str):
    cursor.execute(
        """
        SELECT username, email, website, password_hash, site_token
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    return cursor.fetchone()


def get_user_by_token(site_token: str):
    cursor.execute(
        """
        SELECT username, email, website, password_hash, site_token
        FROM users
        WHERE site_token = ?
        """,
        (site_token,)
    )

    return cursor.fetchone()


def username_exists(username: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    return cursor.fetchone() is not None


def email_exists(email: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM users
        WHERE email = ?
        """,
        (email,)
    )

    return cursor.fetchone() is not None


def verify_user(username: str, password: str) -> bool:
    row = get_user_by_username(username)
    if not row:
        return False

    password_hash = row[3]
    return verify_password(password, password_hash)


def get_total_attacks():

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM attacks
        """
    )

    total = cursor.fetchone()[0]

    return total

def get_last_attack():

    cursor.execute(
        """
        SELECT attack_type
        FROM attacks
        ORDER BY id DESC
        LIMIT 1
        """
    )

    row = cursor.fetchone()

    if row:
        return row[0]

    return "No attacks yet"

def get_all_attacks():

    cursor.execute(
        """
        SELECT *
        FROM attacks
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    return rows

connection.commit()
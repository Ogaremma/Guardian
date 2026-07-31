import sqlite3
from datetime import datetime

connection = sqlite3.connect("guardian.db")
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
connection.commit()
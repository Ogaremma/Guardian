import sqlite3

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

connection.commit()
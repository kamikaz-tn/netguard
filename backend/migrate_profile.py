"""
netguard/backend/migrate_profile.py
─────────────────────────────────────
Run once to add profile columns to the users table.
Usage: python migrate_profile.py

Safe to run multiple times — uses ALTER TABLE IF NOT EXISTS pattern via try/except.
"""

import sqlite3
import os

DB_PATH = os.getenv("DB_PATH", "./data/netguard.db")

MIGRATIONS = [
    "ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN avatar_url TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0",
]

def run():
    print(f"Connecting to: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    for sql in MIGRATIONS:
        try:
            cur.execute(sql)
            col = sql.split("ADD COLUMN")[1].strip().split()[0]
            print(f"  ✓ Added column: {col}")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                col = sql.split("ADD COLUMN")[1].strip().split()[0]
                print(f"  · Already exists: {col}")
            else:
                print(f"  ✗ Error: {e}")

    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    run()

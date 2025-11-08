import sqlite3
import json
import time
import os

DB_PATH = "/home/honeypot/honeypot/mailoney/mailoney.db"
OUT_PATH = "/home/honeypot/honeypot/mailoney/mailoney/logs/mailoney.json"

def export_logs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM smtp_sessions")
    rows = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]
    
    with open(OUT_PATH, "w") as f:
        for row in rows:
            log_entry = dict(zip(columns, row))
            json.dump(log_entry, f)
            f.write("\n")

    conn.close()

if __name__ == "__main__":
    export_logs()

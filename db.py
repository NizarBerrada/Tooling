import sqlite3
import os

DB_FILE = "alerts.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            organization TEXT,
            trusted BOOLEAN,
            score INTEGER,
            info TEXT,
            issues TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_alert(domain, organization, trusted, score, info, issues):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (domain, organization, trusted, score, info, issues)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (domain, organization, trusted, score, info, "\n".join(issues)))
    conn.commit()
    conn.close()

def get_filtered_alerts(min_score=-999, trusted=None):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    query = "SELECT domain, organization, trusted, score, info, issues, timestamp FROM alerts WHERE score >= ?"
    params = [min_score]
    if trusted is not None:
        query += " AND trusted = ?"
        params.append(trusted)
    query += " ORDER BY timestamp DESC"
    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()
    return results

init_db()
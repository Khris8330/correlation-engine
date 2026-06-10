import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import json

DB_PATH = "data/correlation.db"
ANOMALY_DB_PATH = "../network-anomaly-detector/data/network.db"

# -----------------------------
# HELPER
# -----------------------------
def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

# -----------------------------
# DATABASE INITIALIZATION
# -----------------------------
def create_database():
    Path("data").mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ---------------- SCAN RESULTS TABLE ----------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            open_ports TEXT DEFAULT '[]',
            services TEXT DEFAULT '{}',
            os_guess TEXT,
            misconfigurations TEXT DEFAULT '[]',
            attack_surface_score INTEGER DEFAULT 0,
            cve_findings TEXT DEFAULT '[]',
            scanned_at TIMESTAMP
        )
    """)

    # ---------------- CORRELATIONS TABLE ----------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL UNIQUE,
            anomaly_alerts TEXT DEFAULT '[]',
            attack_surface_findings TEXT DEFAULT '[]',
            correlation_score INTEGER DEFAULT 0,
            threat_level TEXT DEFAULT 'NONE',
            threat_summary TEXT,
            timestamp TIMESTAMP
        )
    """)

    # ---------------- CONFIG TABLE ----------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    # ---------------- DEFAULT CONFIG ----------------
    cursor.execute("""
        INSERT OR IGNORE INTO config (key, value)
        VALUES ('anomaly_db_path', ?)
    """, (ANOMALY_DB_PATH,))

    conn.commit()
    conn.close()

# -----------------------------
# CONFIG
# -----------------------------
def get_config(key):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM config WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

# -----------------------------
# ANOMALY DETECTOR READER
# -----------------------------
def get_anomaly_devices():
    path = get_config("anomaly_db_path")
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, mac, is_known, reconnect_count, first_seen, last_seen
        FROM devices
        ORDER BY last_seen DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "ip": r[0],
            "mac": r[1],
            "is_known": bool(r[2]),
            "reconnect_count": r[3],
            "first_seen": r[4],
            "last_seen": r[5]
        }
        for r in rows
    ]

def get_anomaly_alerts(mac=None):
    path = get_config("anomaly_db_path")
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    if mac:
        cursor.execute("""
            SELECT network, alert_type, mac, ip, severity, message, timestamp
            FROM alerts
            WHERE mac = ?
            ORDER BY timestamp DESC
        """, (mac,))
    else:
        cursor.execute("""
            SELECT network, alert_type, mac, ip, severity, message, timestamp
            FROM alerts
            ORDER BY timestamp DESC
        """)
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "network": r[0],
            "alert_type": r[1],
            "mac": r[2],
            "ip": r[3],
            "severity": r[4],
            "message": r[5],
            "timestamp": r[6]
        }
        for r in rows
    ]

# -----------------------------
# SCAN RESULTS
# -----------------------------
def save_scan_result(ip, mac, open_ports, services, os_guess, misconfigurations, score):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if a scan for this MAC already exists
    cursor.execute("SELECT id FROM scan_results WHERE mac = ?", (mac,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE scan_results
            SET ip = ?,
                open_ports = ?,
                services = ?,
                os_guess = ?,
                misconfigurations = ?,
                attack_surface_score = ?,
                scanned_at = ?
            WHERE mac = ?
        """, (
            ip,
            json.dumps(open_ports),
            json.dumps(services),
            os_guess,
            json.dumps(misconfigurations),
            score,
            now_utc(),
            mac
        ))
    else:
        cursor.execute("""
            INSERT INTO scan_results
            (ip, mac, open_ports, services, os_guess, misconfigurations, attack_surface_score, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip, mac,
            json.dumps(open_ports),
            json.dumps(services),
            os_guess,
            json.dumps(misconfigurations),
            score,
            now_utc()
        ))

    conn.commit()
    conn.close()

def get_latest_scan(mac):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, mac, open_ports, services, os_guess, 
               misconfigurations, attack_surface_score, cve_findings, scanned_at
        FROM scan_results
        WHERE mac = ?
        ORDER BY scanned_at DESC
        LIMIT 1
    """, (mac,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "ip": row[0],
        "mac": row[1],
        "open_ports": json.loads(row[2]),
        "services": json.loads(row[3]),
        "os_guess": row[4],
        "misconfigurations": json.loads(row[5]),
        "attack_surface_score": row[6],
        "cve_findings": json.loads(row[7]),
        "scanned_at": row[8]
    }

def get_all_scan_results():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, mac, open_ports, services, os_guess, misconfigurations, attack_surface_score, scanned_at
        FROM scan_results
        ORDER BY scanned_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "ip": row[0],
            "mac": row[1],
            "open_ports": json.loads(row[2]),
            "services": json.loads(row[3]),
            "os_guess": row[4],
            "misconfigurations": json.loads(row[5]),
            "attack_surface_score": row[6],
            "scanned_at": row[7]
        }
        for row in rows
    ]

# -----------------------------
# CORRELATIONS
# -----------------------------
def save_correlation(ip, mac, anomaly_alerts, attack_surface_findings, score, threat_level, summary):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if a correlation for this MAC already exists
    cursor.execute("SELECT id FROM correlations WHERE mac = ?", (mac,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE correlations
            SET ip = ?,
                anomaly_alerts = ?,
                attack_surface_findings = ?,
                correlation_score = ?,
                threat_level = ?,
                threat_summary = ?,
                timestamp = ?
            WHERE mac = ?
        """, (
            ip,
            json.dumps(anomaly_alerts),
            json.dumps(attack_surface_findings),
            score,
            threat_level,
            summary,
            now_utc(),
            mac
        ))
    else:
        cursor.execute("""
            INSERT INTO correlations
            (ip, mac, anomaly_alerts, attack_surface_findings, correlation_score, threat_level, threat_summary, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip, mac,
            json.dumps(anomaly_alerts),
            json.dumps(attack_surface_findings),
            score,
            threat_level,
            summary,
            now_utc()
        ))

    conn.commit()
    conn.close()

def get_all_correlations():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip, mac, anomaly_alerts, attack_surface_findings,
               correlation_score, threat_level, threat_summary, timestamp
        FROM correlations
        ORDER BY correlation_score DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "ip": row[0],
            "mac": row[1],
            "anomaly_alerts": json.loads(row[2]),
            "attack_surface_findings": json.loads(row[3]),
            "correlation_score": row[4],
            "threat_level": row[5],
            "threat_summary": row[6],
            "timestamp": row[7]
        }
        for row in rows
    ]

def get_correlation_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM correlations")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM correlations WHERE threat_level = 'CRITICAL'")
    critical = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM correlations WHERE threat_level = 'HIGH'")
    high = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM correlations WHERE threat_level = 'MEDIUM'")
    medium = cursor.fetchone()[0]
    conn.close()
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium
    }

def save_cve_findings(mac, cve_findings):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scan_results
        SET cve_findings = ?
        WHERE mac = ?
    """, (json.dumps(cve_findings), mac))
    conn.commit()
    conn.close()

def get_cve_findings(mac):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cve_findings FROM scan_results
        WHERE mac = ?
        ORDER BY scanned_at DESC
        LIMIT 1
    """, (mac,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return []
    return json.loads(row[0])

# -----------------------------
# OPTIONAL TEST RUN
# -----------------------------
if __name__ == "__main__":
    create_database()
    print("Correlation database initialized successfully.")

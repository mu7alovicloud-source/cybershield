"""SQLite persistence for scans, incidents, evidence and audit events."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from app.config import DATABASE_FILE

SCHEMA_VERSION = 2


def get_connection():
    con = sqlite3.connect(DATABASE_FILE, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def initialize_database():
    with get_connection() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            risk INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS evidence_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            code TEXT,
            severity TEXT,
            score INTEGER DEFAULT 0,
            detail TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS url_scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            risk INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL NOT NULL,
            reasons_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            target TEXT,
            result TEXT,
            details_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        INSERT OR REPLACE INTO schema_meta(key,value) VALUES('version','2');
        """)


def add_scan(path, sha256, risk, verdict, evidence=None):
    with get_connection() as con:
        cur = con.execute('INSERT INTO scans(path,sha256,risk,verdict) VALUES(?,?,?,?)', (str(path), str(sha256), int(risk), str(verdict)))
        scan_id = cur.lastrowid
        for item in evidence or []:
            con.execute('INSERT INTO evidence_items(scan_id,code,severity,score,detail) VALUES(?,?,?,?,?)',
                         (scan_id, item.get('code'), item.get('severity'), int(item.get('score', 0)), str(item.get('detail', ''))))
        return scan_id


def get_scan_count():
    with get_connection() as con: return con.execute('SELECT COUNT(*) FROM scans').fetchone()[0]


def get_recent_scans(limit=10):
    with get_connection() as con:
        return [tuple(r) for r in con.execute('SELECT path,verdict,risk,created_at FROM scans ORDER BY id DESC LIMIT ?', (int(limit),)).fetchall()]


def add_incident(title, severity, source, status='Open'):
    with get_connection() as con:
        cur = con.execute('INSERT INTO incidents(title,severity,source,status) VALUES(?,?,?,?)', (str(title), str(severity), str(source), str(status)))
        return cur.lastrowid


def get_incidents(status=None):
    with get_connection() as con:
        if status:
            rows = con.execute('SELECT id,title,severity,source,status,created_at FROM incidents WHERE status=? ORDER BY id DESC', (status,)).fetchall()
        else:
            rows = con.execute('SELECT id,title,severity,source,status,created_at FROM incidents ORDER BY id DESC').fetchall()
        return [tuple(r) for r in rows]


def close_incident(incident_id: int):
    with get_connection() as con:
        con.execute('UPDATE incidents SET status=? WHERE id=?', ('Closed', int(incident_id)))
        return con.total_changes > 0


def get_incident_counts():
    with get_connection() as con:
        return dict(con.execute('SELECT severity,COUNT(*) FROM incidents WHERE status != "Closed" GROUP BY severity').fetchall())


def add_url_scan(url, risk, verdict, confidence, reasons):
    with get_connection() as con:
        con.execute('INSERT INTO url_scans(url,risk,verdict,confidence,reasons_json) VALUES(?,?,?,?,?)',
                    (str(url), int(risk), str(verdict), float(confidence), json.dumps(list(reasons or []), ensure_ascii=False)))


def get_recent_url_scans(limit=20):
    with get_connection() as con:
        rows = con.execute('SELECT url,risk,verdict,confidence,reasons_json,created_at FROM url_scans ORDER BY id DESC LIMIT ?', (int(limit),)).fetchall()
        return [dict(r) for r in rows]


def add_audit(action, target=None, result=None, details=None):
    with get_connection() as con:
        con.execute('INSERT INTO audit_logs(action,target,result,details_json) VALUES(?,?,?,?)',
                    (str(action), str(target) if target is not None else None, str(result) if result is not None else None,
                     json.dumps(details or {}, ensure_ascii=False)))


def get_recent_audit(limit=50):
    with get_connection() as con:
        return [dict(r) for r in con.execute('SELECT id,action,target,result,details_json,created_at FROM audit_logs ORDER BY id DESC LIMIT ?', (int(limit),)).fetchall()]


def set_setting(key, value):
    with get_connection() as con:
        con.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (str(key), str(value)))


def get_setting(key, default=None):
    with get_connection() as con:
        r = con.execute('SELECT value FROM settings WHERE key=?', (str(key),)).fetchone()
        return r[0] if r else default

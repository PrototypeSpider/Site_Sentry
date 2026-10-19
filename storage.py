"""SQLite persistence with a versioned initial migration."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 3


class ScanStore:
    def __init__(self, database_path: str):
        self.database_path = database_path
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    def connect(self):
        conn = sqlite3.connect(self.database_path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def migrate(self):
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise RuntimeError("Database schema is newer than this application.")
            if version < 1:
                conn.executescript("CREATE TABLE scans(scan_id TEXT PRIMARY KEY,target TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,finished_at TEXT,result_json TEXT,error TEXT); CREATE INDEX scans_created_at_idx ON scans(created_at); CREATE TABLE audit_events(event_id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id TEXT,action TEXT NOT NULL,timestamp TEXT NOT NULL,outcome TEXT NOT NULL,FOREIGN KEY(scan_id) REFERENCES scans(scan_id)); PRAGMA user_version=1;")
                version = 1
            if version < 2:
                conn.execute("CREATE INDEX scans_created_status_idx ON scans(created_at,status)")
                conn.execute("PRAGMA user_version=2")
                version = 2
            if version < 3:
                conn.execute("ALTER TABLE scans ADD COLUMN profile TEXT NOT NULL DEFAULT 'standard'")
                conn.execute("PRAGMA user_version=3")

    def count_created_since(self, since: str) -> int:
        with self.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM scans WHERE created_at >= ? AND status != 'rejected'", (since,)).fetchone()[0])

    def create_scan(self, scan_id: str, target: str, created_at: str, profile: str = "standard"):
        with self.connect() as conn:
            conn.execute("INSERT INTO scans(scan_id,target,status,created_at,profile) VALUES(?,?,?,?,?)", (scan_id,target,"queued",created_at,profile))
            self.audit(scan_id,"scan_created",created_at,"accepted",conn)

    def update_status(self, scan_id: str, status: str, *, result=None, error=None, finished_at=None):
        with self.connect() as conn:
            conn.execute("UPDATE scans SET status=?,result_json=COALESCE(?,result_json),error=?,finished_at=COALESCE(?,finished_at) WHERE scan_id=?", (status,json.dumps(result,ensure_ascii=False) if result is not None else None,error,finished_at,scan_id))
            self.audit(scan_id,"scan_status",finished_at or "",status,conn)

    def get_scan(self, scan_id: str):
        with self.connect() as conn:
            row=conn.execute("SELECT * FROM scans WHERE scan_id=?",(scan_id,)).fetchone()
        if not row: return None
        result=dict(row); encoded=result.pop("result_json"); result["result"]=json.loads(encoded) if encoded else None
        return result

    def get_status(self,scan_id: str)->str|None:
        with self.connect() as conn:
            row=conn.execute("SELECT status FROM scans WHERE scan_id=?",(scan_id,)).fetchone()
        return row["status"] if row else None

    def list_scans(self, limit=100):
        with self.connect() as conn:
            rows=conn.execute("SELECT scan_id,target,status,created_at,finished_at,error,profile FROM scans ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def audit(scan_id,action,timestamp,outcome,conn):
        conn.execute("INSERT INTO audit_events(scan_id,action,timestamp,outcome) VALUES(?,?,?,?)",(scan_id,action,timestamp,outcome))

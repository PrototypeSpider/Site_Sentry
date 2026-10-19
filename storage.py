"""SQLite persistence with a versioned initial migration."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 5


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
                version = 3
            if version < 4:
                conn.execute("ALTER TABLE scans ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''")
                conn.execute("CREATE INDEX scans_owner_created_idx ON scans(owner_id,created_at)")
                conn.execute("PRAGMA user_version=4")
                version = 4
            if version < 5:
                conn.execute("CREATE TABLE finding_workflow(scan_id TEXT NOT NULL,check_id TEXT NOT NULL,owner_id TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('acknowledged','fixed')),note TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL,PRIMARY KEY(scan_id,check_id),FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE)")
                conn.execute("CREATE INDEX finding_workflow_owner_idx ON finding_workflow(owner_id,updated_at)")
                conn.execute("PRAGMA user_version=5")

    def count_created_since(self, since: str) -> int:
        with self.connect() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM scans WHERE created_at >= ? AND status != 'rejected'", (since,)).fetchone()[0])

    def create_scan(self, scan_id: str, target: str, created_at: str, profile: str = "standard", owner_id: str = ""):
        with self.connect() as conn:
            conn.execute("INSERT INTO scans(scan_id,target,status,created_at,profile,owner_id) VALUES(?,?,?,?,?,?)", (scan_id,target,"queued",created_at,profile,owner_id))
            self.audit(scan_id,"scan_created",created_at,"accepted",conn)

    def update_status(self, scan_id: str, status: str, *, result=None, error=None, finished_at=None):
        with self.connect() as conn:
            conn.execute("UPDATE scans SET status=?,result_json=COALESCE(?,result_json),error=?,finished_at=COALESCE(?,finished_at) WHERE scan_id=?", (status,json.dumps(result,ensure_ascii=False) if result is not None else None,error,finished_at,scan_id))
            self.audit(scan_id,"scan_status",finished_at or "",status,conn)

    def get_scan(self, scan_id: str, owner_id: str | None = None):
        with self.connect() as conn:
            if owner_id is None:
                row=conn.execute("SELECT * FROM scans WHERE scan_id=?",(scan_id,)).fetchone()
            else:
                row=conn.execute("SELECT * FROM scans WHERE scan_id=? AND owner_id=?",(scan_id,owner_id)).fetchone()
        if not row: return None
        result=dict(row); encoded=result.pop("result_json"); result["result"]=json.loads(encoded) if encoded else None
        return result

    def get_status(self,scan_id: str)->str|None:
        with self.connect() as conn:
            row=conn.execute("SELECT status FROM scans WHERE scan_id=?",(scan_id,)).fetchone()
        return row["status"] if row else None

    def list_scans(self, limit=100, owner_id: str | None = None):
        with self.connect() as conn:
            if owner_id is None:
                rows=conn.execute("SELECT scan_id,target,status,created_at,finished_at,error,profile FROM scans ORDER BY created_at DESC LIMIT ?",(limit,)).fetchall()
            else:
                rows=conn.execute("SELECT scan_id,target,status,created_at,finished_at,error,profile FROM scans WHERE owner_id=? ORDER BY created_at DESC LIMIT ?",(owner_id,limit)).fetchall()
        return [dict(row) for row in rows]

    def get_workflows(self, scan_id: str, owner_id: str) -> dict[str, dict]:
        with self.connect() as conn:
            rows = conn.execute("SELECT check_id,status,note,updated_at FROM finding_workflow WHERE scan_id=? AND owner_id=?", (scan_id, owner_id)).fetchall()
        return {row["check_id"]: dict(row) for row in rows}

    def set_workflow(self, scan_id: str, check_id: str, owner_id: str, status: str, note: str, updated_at: str):
        with self.connect() as conn:
            conn.execute("INSERT INTO finding_workflow(scan_id,check_id,owner_id,status,note,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(scan_id,check_id) DO UPDATE SET status=excluded.status,note=excluded.note,updated_at=excluded.updated_at WHERE finding_workflow.owner_id=excluded.owner_id",
                (scan_id, check_id, owner_id, status, note, updated_at))
            saved = conn.execute("SELECT owner_id FROM finding_workflow WHERE scan_id=? AND check_id=?", (scan_id, check_id)).fetchone()
            if not saved or saved["owner_id"] != owner_id:
                raise PermissionError("Finding workflow belongs to another identity.")
            self.audit(scan_id, "finding_workflow", updated_at, status, conn)

    def delete_workflow(self, scan_id: str, check_id: str, owner_id: str, updated_at: str):
        with self.connect() as conn:
            conn.execute("DELETE FROM finding_workflow WHERE scan_id=? AND check_id=? AND owner_id=?", (scan_id, check_id, owner_id))
            self.audit(scan_id, "finding_workflow", updated_at, "reopened", conn)

    @staticmethod
    def audit(scan_id,action,timestamp,outcome,conn):
        conn.execute("INSERT INTO audit_events(scan_id,action,timestamp,outcome) VALUES(?,?,?,?)",(scan_id,action,timestamp,outcome))

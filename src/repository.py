from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (NOTICE_KIND, NOTICE_STATUS_ACTIVE, RECORD_STATUS_CLOSED,
                    RECORD_STATUS_OPEN, STATES)


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._txn_depth = 0
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    @contextmanager
    def transaction(self):
        with self._lock:
            if self._txn_depth == 0:
                self._txn_depth = 1
                try:
                    self.conn.execute("BEGIN IMMEDIATE")
                    yield self
                    self.conn.commit()
                except Exception:
                    self.conn.rollback()
                    raise
                finally:
                    self._txn_depth = 0
            else:
                self._txn_depth += 1
                try:
                    yield self
                finally:
                    self._txn_depth -= 1

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.transaction():
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    external_ref TEXT,
                    source TEXT NOT NULL DEFAULT 'center',
                    valid_until TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE INDEX IF NOT EXISTS ix_records_item_kind ON records(item_id, kind);
                CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    advice TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    basis_hash TEXT NOT NULL,
                    basis_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','superseded','invalidated')),
                    invalid_reason TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    invalidated_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_recommendation_active
                    ON recommendations(item_id) WHERE status='active';
                CREATE TABLE IF NOT EXISTS merge_conflicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_no TEXT NOT NULL,
                    item_id INTEGER,
                    request_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','resolved')),
                    center_copy TEXT NOT NULL,
                    local_copy TEXT NOT NULL,
                    resolution TEXT,
                    resolved_by TEXT,
                    resolved_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_conflicts_status ON merge_conflicts(status);
                CREATE TABLE IF NOT EXISTS processed_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL UNIQUE,
                    operation TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'applied',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
            """)
            self._migrate_columns()

    def _migrate_columns(self) -> None:
        columns = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(records)")
        }
        migrations = {
            "source": "ALTER TABLE records ADD COLUMN source TEXT NOT NULL DEFAULT 'center'",
            "valid_until": "ALTER TABLE records ADD COLUMN valid_until TEXT",
            "updated_at": "ALTER TABLE records ADD COLUMN updated_at TEXT",
        }
        for name, sql in migrations.items():
            if name not in columns:
                self.conn.execute(sql)
                self.conn.execute(
                    "UPDATE records SET updated_at=COALESCE(updated_at, created_at)"
                )

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self.transaction():
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def get_item_by_external_ref(self, external_ref: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM items WHERE external_ref=?", (external_ref,)
            ).fetchone()
        return self._item(row) if row else None

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self.transaction():
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM items WHERE id=?", (item_id,)
                ).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def update_measurement(self, item_id: int, severity: Optional[str],
                           quantity: Optional[float], threshold: Optional[float],
                           expected_version: int, actor: str) -> Dict[str, Any]:
        item = self.get_item(item_id)
        severity = severity if severity is not None else item["severity"]
        quantity = quantity if quantity is not None else item["quantity"]
        threshold = threshold if threshold is not None else item["threshold"]
        now = utc_now()
        with self.transaction():
            cur = self.conn.execute(
                """UPDATE items SET severity=?, quantity=?, threshold=?, version=version+1,
                   updated_at=? WHERE id=? AND version=?""",
                (severity, quantity, threshold, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str,
                   source: str = "center",
                   valid_until: Optional[str] = None) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self.transaction():
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       source, valid_until, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, source, valid_until,
                     actor, now, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        return self.get_record(record_id)

    def get_record(self, record_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM records WHERE id=?", (record_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("记录不存在")
        return dict(row)

    def find_record(self, item_id: int, kind: str,
                    external_ref: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? AND kind=? AND external_ref=?",
                (item_id, kind, external_ref),
            ).fetchone()
        return dict(row) if row else None

    def update_record(self, record_id: int, **changes: Any) -> Dict[str, Any]:
        if not changes:
            return self.get_record(record_id)
        self.get_record(record_id)
        fields = [f"{key}=?" for key in changes]
        fields.append("updated_at=?")
        params = list(changes.values()) + [utc_now(), record_id]
        with self.transaction():
            cur = self.conn.execute(
                f"UPDATE records SET {', '.join(fields)} WHERE id=?", params
            )
            if cur.rowcount == 0:
                raise NotFoundError("记录不存在")
        return self.get_record(record_id)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def expire_active_notices(self, item_id: int) -> List[Dict[str, Any]]:
        from datetime import datetime, timezone
        now = utc_now()
        current = datetime.now(timezone.utc)
        expired = []
        with self.transaction():
            rows = self.conn.execute(
                """SELECT * FROM records WHERE item_id=? AND kind=? AND status=?
                   AND valid_until IS NOT NULL""",
                (item_id, NOTICE_KIND, NOTICE_STATUS_ACTIVE),
            ).fetchall()
            for row in rows:
                end = datetime.fromisoformat(row["valid_until"].replace("Z", "+00:00"))
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
                if end > current:
                    continue
                self.conn.execute(
                    "UPDATE records SET status='expired', updated_at=? WHERE id=?",
                    (now, row["id"]),
                )
                changed = dict(row)
                changed.update({"status": "expired", "updated_at": now})
                expired.append(changed)
        return expired

    def replace_recommendation(self, item_id: int, calculation: Dict[str, Any],
                               actor: str, invalid_reason: Optional[str] = None,
                               invalidate_only: bool = False) -> Dict[str, Any]:
        now = utc_now()
        with self.transaction():
            self.conn.execute(
                """UPDATE recommendations SET status='superseded', invalidated_at=?
                   WHERE item_id=? AND status='active'""",
                (now, item_id),
            )
            if invalidate_only:
                recommendation_id = None
            else:
                cur = self.conn.execute(
                    """INSERT INTO recommendations(item_id, advice, reason, basis_hash,
                       basis_json, status, invalid_reason, created_by, created_at)
                       VALUES(?,?,?,?,?,'active',?,?,?)""",
                    (item_id, calculation["advice"], calculation["reason"],
                     calculation["basis_hash"],
                     json.dumps(calculation, ensure_ascii=False, sort_keys=True,
                                default=str),
                     invalid_reason, actor, now),
                )
                recommendation_id = int(cur.lastrowid)
        if recommendation_id is None:
            return {}
        return self.get_recommendation(recommendation_id)

    def get_recommendation(self, recommendation_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM recommendations WHERE id=?", (recommendation_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("限行建议不存在")
        result = dict(row)
        result["basis"] = json.loads(result.pop("basis_json"))
        return result

    def get_active_recommendation(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM recommendations WHERE item_id=? AND status='active'",
                (item_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["basis"] = json.loads(result.pop("basis_json"))
        return result

    def list_recommendations(self, item_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM recommendations"
        params: tuple = ()
        if item_id is not None:
            sql += " WHERE item_id=?"
            params = (item_id,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["basis"] = json.loads(value.pop("basis_json"))
            result.append(value)
        return result

    def create_conflict(self, ticket_no: str, item_id: Optional[int],
                        request_id: str, center_copy: dict, local_copy: dict,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self.transaction():
                cur = self.conn.execute(
                    """INSERT INTO merge_conflicts(ticket_no, item_id, request_id, status,
                       center_copy, local_copy, created_by, created_at)
                       VALUES(?,?,?,'open',?,?,?,?)""",
                    (ticket_no, item_id, request_id,
                     json.dumps(center_copy, ensure_ascii=False, default=str),
                     json.dumps(local_copy, ensure_ascii=False, default=str),
                     actor, now),
                )
                conflict_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            existing = self.get_conflict_by_request(request_id)
            if existing:
                return existing
            raise ConflictError("请求编号已用于不同结果") from exc
        return self.get_conflict(conflict_id)

    def get_conflict(self, conflict_id: int) -> Dict[str, Any]:
        with self._list_conflicts_lock():
            row = self.conn.execute(
                "SELECT * FROM merge_conflicts WHERE id=?", (conflict_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("冲突不存在")
        return self._conflict(row)

    def get_conflict_by_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM merge_conflicts WHERE request_id=?", (request_id,)
            ).fetchone()
        return self._conflict(row) if row else None

    def _list_conflicts_lock(self):
        return self._lock

    def list_conflicts(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM merge_conflicts"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._conflict(row) for row in rows]

    @staticmethod
    def _conflict(row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        result["center_copy"] = json.loads(result["center_copy"])
        result["local_copy"] = json.loads(result["local_copy"])
        return result

    def resolve_conflict(self, conflict_id: int, resolution: str,
                         actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self.transaction():
            cur = self.conn.execute(
                """UPDATE merge_conflicts SET status='resolved', resolution=?,
                   resolved_by=?, resolved_at=? WHERE id=? AND status='open'""",
                (resolution, actor, now, conflict_id),
            )
            if cur.rowcount == 0:
                if self.conn.execute(
                    "SELECT 1 FROM merge_conflicts WHERE id=?", (conflict_id,)
                ).fetchone() is None:
                    raise NotFoundError("冲突不存在")
                raise ConflictError("冲突已确认")
        return self.get_conflict(conflict_id)

    def save_processed_request(self, request_id: str, operation: str,
                               fingerprint: str, response: dict) -> None:
        with self.transaction():
            self.conn.execute(
                """INSERT INTO processed_requests(request_id, operation, fingerprint,
                   response_json, status, created_at) VALUES(?,?,?,?,'applied',?)""",
                (request_id, operation, fingerprint,
                 json.dumps(response, ensure_ascii=False, default=str), utc_now()),
            )

    def get_processed_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM processed_requests WHERE request_id=?", (request_id,)
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["response"] = json.loads(result.pop("response_json"))
        return result

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self.transaction():
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        event["id"] = int(event_id)
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()

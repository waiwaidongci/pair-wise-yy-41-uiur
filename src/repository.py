from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import calculate_hash, make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (ENTITY, ID_PREFIX, STATES, compute_recommendation, snapshot_payload)


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
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
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    valid_until TEXT,
                    payload TEXT,
                    expiry_audited INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
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
                CREATE TABLE IF NOT EXISTS drafts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_no TEXT NOT NULL UNIQUE,
                    order_no TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    base_hash TEXT,
                    status TEXT NOT NULL DEFAULT 'draft'
                        CHECK(status IN ('draft','merged','pending_confirmation')),
                    result TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_drafts_order_no ON drafts(order_no);
                CREATE INDEX IF NOT EXISTS idx_drafts_status ON drafts(status);
                CREATE TABLE IF NOT EXISTS recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    order_no TEXT NOT NULL,
                    item_id INTEGER,
                    level TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active','invalid')),
                    reason TEXT NOT NULL,
                    based_on TEXT NOT NULL,
                    computed_at TEXT NOT NULL,
                    invalidated_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_recommendations_order
                    ON recommendations(order_no, status);
                CREATE TABLE IF NOT EXISTS request_log (
                    request_no TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('completed','failed')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
        self._migrate_records_columns()

    def _migrate_records_columns(self) -> None:
        """为旧库补齐 records 表的通告有效期/载荷/失效标记列。"""
        with self._lock, self.conn:
            cols = {row[1] for row in self.conn.execute("PRAGMA table_info(records)").fetchall()}
            if "valid_until" not in cols:
                self.conn.execute("ALTER TABLE records ADD COLUMN valid_until TEXT")
            if "payload" not in cols:
                self.conn.execute("ALTER TABLE records ADD COLUMN payload TEXT")
            if "expiry_audited" not in cols:
                self.conn.execute(
                    "ALTER TABLE records ADD COLUMN expiry_audited INTEGER NOT NULL DEFAULT 0")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
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
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

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

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
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

    # ---------- 限行链：原子写入（状态变更 + 审计 + 请求幂等同一事务） ----------

    def _append_audit_tx(self, conn, action, entity_type, entity_id, actor, detail):
        row = conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]))
        return event

    def _upsert_request_tx(self, conn, request_no, action, result, status):
        now = utc_now()
        conn.execute(
            """INSERT INTO request_log(request_no, action, result, status, created_at, updated_at)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(request_no) DO UPDATE SET result=excluded.result,
                 status=excluded.status, updated_at=excluded.updated_at""",
            (request_no, action, json.dumps(result, ensure_ascii=False, sort_keys=True),
             status, now, now))

    def _replay_request_tx(self, conn, request_no):
        row = conn.execute(
            "SELECT result, status FROM request_log WHERE request_no=?", (request_no,)
        ).fetchone()
        if row is not None and row["status"] == "completed":
            return json.loads(row["result"]), True
        return None, False

    def _item_by_order_tx(self, conn, order_no):
        row = conn.execute(
            "SELECT * FROM items WHERE external_ref=?", (order_no,)).fetchone()
        return dict(row) if row else None

    def _records_tx(self, conn, item_id):
        rows = conn.execute(
            "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)).fetchall()
        return [dict(r) for r in rows]

    def snapshot_hash(self, order_no):
        with self._lock:
            item = self._item_by_order_tx(self.conn, order_no)
            if item is None:
                return None
            records = self._records_tx(self.conn, item["id"])
        return calculate_hash("SNAPSHOT", snapshot_payload(item, records))

    def _recompute_tx(self, conn, order_no, actor, reason):
        """在同一事务内按当前告警/核查/通告状态重算限行建议，失效旧建议并留审计。"""
        item = self._item_by_order_tx(conn, order_no)
        if item is None:
            return None
        records = self._records_tx(conn, item["id"])
        now = utc_now()
        verification_open = any(r["kind"] == "verification" and r["status"] == "open"
                                for r in records)
        valid_notice = any(
            r["kind"] == "notice" and r["status"] == "open"
            and (r.get("valid_until") is None or r["valid_until"] > now)
            for r in records
        )
        based_on = calculate_hash("SNAPSHOT", snapshot_payload(item, records))
        active = conn.execute(
            """SELECT * FROM recommendations WHERE order_no=? AND status='active'
               ORDER BY id DESC LIMIT 1""", (order_no,)).fetchone()
        if active is not None and active["based_on"] == based_on:
            return dict(active)
        if active is not None:
            conn.execute(
                "UPDATE recommendations SET status='invalid', invalidated_at=? WHERE id=?",
                (now, active["id"]))
            self._append_audit_tx(
                conn, "recommendation_invalidated", "recommendation", active["id"], actor,
                {"order_no": order_no, "reason": reason, "previous_level": active["level"]})
        level, rec_reason = compute_recommendation(
            item["severity"], item["quantity"], item["threshold"],
            verification_open, valid_notice)
        cur = conn.execute(
            """INSERT INTO recommendations(order_no, item_id, level, status, reason,
               based_on, computed_at, invalidated_at) VALUES(?,?,?,?,?,?,?,?)""",
            (order_no, item["id"], level, "active", rec_reason, based_on, now, None))
        rec_id = int(cur.lastrowid)
        self._append_audit_tx(
            conn, "recommendation_computed", "recommendation", rec_id, actor,
            {"order_no": order_no, "level": level, "reason": rec_reason, "trigger": reason})
        row = conn.execute("SELECT * FROM recommendations WHERE id=?", (rec_id,)).fetchone()
        return dict(row)

    def register_alert(self, order_no, title, description, severity, quantity, threshold,
                       request_no, actor):
        now = utc_now()
        with self._lock, self.conn:
            replay, done = self._replay_request_tx(self.conn, request_no)
            if done:
                return replay
            if self._item_by_order_tx(self.conn, order_no) is not None:
                raise ConflictError("现场单号已存在告警")
            cur = self.conn.execute(
                """INSERT INTO items(title, description, severity, quantity, threshold,
                   status, version, external_ref, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (title, description, severity, quantity, threshold, STATES[0], 1,
                 order_no, actor, now, now))
            item_id = int(cur.lastrowid)
            recommendation = self._recompute_tx(self.conn, order_no, actor, "alert_registered")
            self._append_audit_tx(
                self.conn, "alert_registered", ENTITY, item_id, actor,
                {"order_no": order_no, "title": title, "severity": severity,
                 "quantity": quantity, "threshold": threshold,
                 "recommendation": recommendation["level"] if recommendation else None})
            item = self._item_by_order_tx(self.conn, order_no)
            result = {"item": item, "recommendation": recommendation}
            self._upsert_request_tx(self.conn, request_no, "alert_registered", result, "completed")
        return result

    def register_record(self, order_no, kind, detail, status, external_ref, valid_until,
                        payload, request_no, actor):
        now = utc_now()
        with self._lock, self.conn:
            replay, done = self._replay_request_tx(self.conn, request_no)
            if done:
                return replay
            item = self._item_by_order_tx(self.conn, order_no)
            if item is None:
                raise NotFoundError("现场单号不存在")
            item_id = item["id"]
            if external_ref is not None:
                dup = self.conn.execute(
                    "SELECT 1 FROM records WHERE item_id=? AND external_ref=?",
                    (item_id, external_ref)).fetchone()
                if dup is not None:
                    raise ConflictError("记录编号已存在")
            cur = self.conn.execute(
                """INSERT INTO records(item_id, kind, detail, status, external_ref,
                   valid_until, payload, expiry_audited, created_by, created_at)
                   VALUES(?,?,?,?,?,?,?,0,?,?)""",
                (item_id, kind, detail, status, external_ref, valid_until,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True), actor, now))
            record_id = int(cur.lastrowid)
            recommendation = self._recompute_tx(self.conn, order_no, actor, f"{kind}_registered")
            self._append_audit_tx(
                self.conn, "record_registered", ENTITY, item_id, actor,
                {"order_no": order_no, "record_id": record_id, "kind": kind, "status": status,
                 "external_ref": external_ref, "valid_until": valid_until,
                 "recommendation": recommendation["level"] if recommendation else None})
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
            result = {"record": dict(row), "recommendation": recommendation}
            self._upsert_request_tx(self.conn, request_no, "record_registered", result, "completed")
        return result

    def update_monitoring(self, order_no, quantity, threshold, severity, expected_version,
                          request_no, actor):
        now = utc_now()
        with self._lock, self.conn:
            replay, done = self._replay_request_tx(self.conn, request_no)
            if done:
                return replay
            item = self._item_by_order_tx(self.conn, order_no)
            if item is None:
                raise NotFoundError("现场单号不存在")
            if expected_version is not None and item["version"] != expected_version:
                raise ConflictError("版本冲突，请刷新后重试")
            self.conn.execute(
                """UPDATE items SET quantity=?, threshold=?, severity=?, version=version+1,
                   updated_at=? WHERE id=?""",
                (quantity, threshold, severity, now, item["id"]))
            recommendation = self._recompute_tx(self.conn, order_no, actor, "monitoring_changed")
            self._append_audit_tx(
                self.conn, "monitoring_updated", ENTITY, item["id"], actor,
                {"order_no": order_no, "quantity": quantity, "threshold": threshold,
                 "severity": severity, "expected_version": expected_version,
                 "recommendation": recommendation["level"] if recommendation else None})
            item = self._item_by_order_tx(self.conn, order_no)
            result = {"item": item, "recommendation": recommendation}
            self._upsert_request_tx(self.conn, request_no, "monitoring_updated", result, "completed")
        return result

    def save_draft(self, request_no, order_no, kind, payload, base_hash, actor):
        now = utc_now()
        with self._lock, self.conn:
            replay, done = self._replay_request_tx(self.conn, request_no)
            if done:
                return replay
            self.conn.execute(
                """INSERT INTO drafts(request_no, order_no, kind, payload, base_hash,
                   status, result, created_at, updated_at)
                   VALUES(?,?,?,?,?, 'draft', NULL, ?, ?)
                   ON CONFLICT(request_no) DO UPDATE SET order_no=excluded.order_no,
                     kind=excluded.kind, payload=excluded.payload, base_hash=excluded.base_hash,
                     status='draft', result=NULL, updated_at=excluded.updated_at""",
                (request_no, order_no, kind,
                 json.dumps(payload, ensure_ascii=False, sort_keys=True), base_hash, now, now))
            row = self.conn.execute("SELECT * FROM drafts WHERE request_no=?",
                                    (request_no,)).fetchone()
            draft = dict(row)
            self._append_audit_tx(
                self.conn, "draft_saved", "draft", draft["id"], actor,
                {"request_no": request_no, "order_no": order_no, "kind": kind})
            result = {"draft": draft}
            self._upsert_request_tx(self.conn, request_no, "draft_saved", result, "completed")
        return result

    def list_drafts(self, status=None):
        sql = "SELECT * FROM drafts"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_draft(self, draft_id):
        with self._lock:
            row = self.conn.execute("SELECT * FROM drafts WHERE id=?", (draft_id,)).fetchone()
            if row is None:
                raise NotFoundError("草稿不存在")
            return dict(row)

    def merge_drafts(self, actor):
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM drafts WHERE status='draft' ORDER BY id").fetchall()
            drafts = [dict(r) for r in rows]
        outcomes = [self._merge_one(draft, actor) for draft in drafts]
        return {"outcomes": outcomes}

    def _merge_one(self, draft, actor):
        request_no = draft["request_no"]
        order_no = draft["order_no"]
        kind = draft["kind"]
        payload = json.loads(draft["payload"])
        with self._lock, self.conn:
            if draft["status"] != "draft":
                return {"request_no": request_no, "outcome": draft["status"]}
            center = self._item_by_order_tx(self.conn, order_no)
            if center is None:
                if kind == "alert":
                    self._apply_alert_tx(self.conn, order_no, payload, actor)
                    outcome, reason = "merged", None
                else:
                    outcome, reason = "pending_confirmation", "现场告警不存在，无法补录核查/通告"
            else:
                if kind == "alert":
                    outcome, reason = self._merge_alert_tx(
                        self.conn, order_no, payload, draft["base_hash"])
                else:
                    outcome, reason = self._merge_record_tx(
                        self.conn, order_no, kind, payload, draft["base_hash"], actor)
            now = utc_now()
            self.conn.execute(
                "UPDATE drafts SET status=?, result=?, updated_at=? WHERE id=?",
                (outcome, json.dumps({"outcome": outcome, "reason": reason},
                                     ensure_ascii=False), now, draft["id"]))
            if outcome == "pending_confirmation":
                self._append_audit_tx(
                    self.conn, "merge_conflict", "draft", draft["id"], actor,
                    {"request_no": request_no, "order_no": order_no, "kind": kind,
                     "reason": reason, "center_untouched": True})
            else:
                self._append_audit_tx(
                    self.conn, "draft_merged", "draft", draft["id"], actor,
                    {"request_no": request_no, "order_no": order_no, "kind": kind})
                self._recompute_tx(self.conn, order_no, actor, "draft_merged")
        return {"request_no": request_no, "outcome": outcome, "reason": reason}

    def _apply_alert_tx(self, conn, order_no, payload, actor):
        now = utc_now()
        conn.execute(
            """INSERT INTO items(title, description, severity, quantity, threshold,
               status, version, external_ref, created_by, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (payload.get("title"), payload.get("description"), payload.get("severity"),
             float(payload.get("quantity", 0)), float(payload.get("threshold", 1)),
             STATES[0], 1, order_no, actor, now, now))

    def _insert_record_tx(self, conn, item_id, kind, payload, actor):
        now = utc_now()
        conn.execute(
            """INSERT INTO records(item_id, kind, detail, status, external_ref,
               valid_until, payload, expiry_audited, created_by, created_at)
               VALUES(?,?,?,?,?,?,?,0,?,?)""",
            (item_id, kind, payload.get("detail"), payload.get("status", "open"),
             payload.get("external_ref"), payload.get("valid_until"),
             json.dumps(payload, ensure_ascii=False, sort_keys=True), actor, now))

    def _update_record_tx(self, conn, record_id, payload):
        conn.execute(
            "UPDATE records SET detail=?, status=?, valid_until=?, payload=? WHERE id=?",
            (payload.get("detail"), payload.get("status", "open"),
             payload.get("valid_until"),
             json.dumps(payload, ensure_ascii=False, sort_keys=True), record_id))

    def _merge_alert_tx(self, conn, order_no, payload, base_hash):
        center = self._item_by_order_tx(conn, order_no)
        center_hash = calculate_hash(
            "SNAPSHOT", snapshot_payload(center, self._records_tx(conn, center["id"])))
        local_same = (
            payload.get("title") == center["title"]
            and payload.get("description") == center["description"]
            and payload.get("severity") == center["severity"]
            and float(payload.get("quantity", 0)) == center["quantity"]
            and float(payload.get("threshold", 1)) == center["threshold"]
        )
        if base_hash is not None and base_hash == center_hash:
            if local_same:
                return "merged", None
            conn.execute(
                """UPDATE items SET title=?, description=?, severity=?, quantity=?,
                   threshold=?, version=version+1, updated_at=? WHERE id=?""",
                (payload.get("title"), payload.get("description"), payload.get("severity"),
                 float(payload.get("quantity", 0)), float(payload.get("threshold", 1)),
                 utc_now(), center["id"]))
            return "merged", None
        if local_same:
            return "merged", None
        return "pending_confirmation", "告警两边都改过，待确认"

    def _merge_record_tx(self, conn, order_no, kind, payload, base_hash, actor):
        center = self._item_by_order_tx(conn, order_no)
        center_hash = calculate_hash(
            "SNAPSHOT", snapshot_payload(center, self._records_tx(conn, center["id"])))
        center_unchanged = (base_hash is not None and base_hash == center_hash)
        external_ref = payload.get("external_ref")
        existing = None
        if external_ref is not None:
            existing = conn.execute(
                "SELECT * FROM records WHERE item_id=? AND external_ref=?",
                (center["id"], external_ref)).fetchone()
        if existing is None:
            self._insert_record_tx(conn, center["id"], kind, payload, actor)
            return "merged", None
        existing = dict(existing)
        local_same = (
            existing["kind"] == kind
            and existing["detail"] == payload.get("detail")
            and existing["status"] == payload.get("status", "open")
            and (existing.get("valid_until") or None) == (payload.get("valid_until") or None)
        )
        if local_same:
            return "merged", None
        if center_unchanged:
            self._update_record_tx(conn, existing["id"], payload)
            return "merged", None
        return "pending_confirmation", "核查/通告两边都改过，待确认"

    def resolve_pending(self, draft_id, keep, actor):
        with self._lock, self.conn:
            row = self.conn.execute("SELECT * FROM drafts WHERE id=?", (draft_id,)).fetchone()
            if row is None:
                raise NotFoundError("草稿不存在")
            draft = dict(row)
            if draft["status"] != "pending_confirmation":
                raise ConflictError("仅待确认草稿可处理")
            if keep == "local" and draft["kind"] == "notice":
                raise ConflictError("不能覆盖中心通告")
            now = utc_now()
            if keep == "center":
                self.conn.execute(
                    "UPDATE drafts SET status='merged', result=?, updated_at=? WHERE id=?",
                    (json.dumps({"outcome": "kept_center"}, ensure_ascii=False), now, draft_id))
                self._append_audit_tx(
                    self.conn, "pending_resolved", "draft", draft_id, actor,
                    {"request_no": draft["request_no"], "keep": "center"})
            else:
                payload = json.loads(draft["payload"])
                order_no = draft["order_no"]
                center = self._item_by_order_tx(self.conn, order_no)
                if center is None:
                    if draft["kind"] == "alert":
                        self._apply_alert_tx(self.conn, order_no, payload, actor)
                    else:
                        raise NotFoundError("现场告警不存在")
                elif draft["kind"] == "alert":
                    self.conn.execute(
                        """UPDATE items SET title=?, description=?, severity=?, quantity=?,
                           threshold=?, version=version+1, updated_at=? WHERE id=?""",
                        (payload.get("title"), payload.get("description"),
                         payload.get("severity"), float(payload.get("quantity", 0)),
                         float(payload.get("threshold", 1)), now, center["id"]))
                else:
                    external_ref = payload.get("external_ref")
                    existing = None
                    if external_ref:
                        existing = self.conn.execute(
                            "SELECT * FROM records WHERE item_id=? AND external_ref=?",
                            (center["id"], external_ref)).fetchone()
                    if existing is None:
                        self._insert_record_tx(self.conn, center["id"], draft["kind"],
                                               payload, actor)
                    else:
                        self._update_record_tx(self.conn, existing["id"], payload)
                self.conn.execute(
                    "UPDATE drafts SET status='merged', result=?, updated_at=? WHERE id=?",
                    (json.dumps({"outcome": "kept_local"}, ensure_ascii=False), now, draft_id))
                self._append_audit_tx(
                    self.conn, "pending_resolved", "draft", draft_id, actor,
                    {"request_no": draft["request_no"], "keep": "local"})
                self._recompute_tx(self.conn, order_no, actor, "pending_resolved")
            row = self.conn.execute("SELECT * FROM drafts WHERE id=?", (draft_id,)).fetchone()
            return {"draft": dict(row)}

    def check_expired_notices(self, actor):
        now = utc_now()
        with self._lock:
            rows = self.conn.execute(
                """SELECT r.*, i.external_ref AS order_no FROM records r
                   JOIN items i ON i.id = r.item_id
                   WHERE r.kind='notice' AND r.status='open'
                     AND r.valid_until IS NOT NULL AND r.valid_until <= ?
                     AND r.expiry_audited=0""",
                (now,)).fetchall()
            notices = [dict(r) for r in rows]
        expired = []
        for notice in notices:
            with self._lock, self.conn:
                self.conn.execute(
                    "UPDATE records SET expiry_audited=1 WHERE id=?", (notice["id"],))
                self._append_audit_tx(
                    self.conn, "notice_expired", "record", notice["id"], actor,
                    {"order_no": notice["order_no"], "external_ref": notice["external_ref"],
                     "valid_until": notice["valid_until"]})
                recommendation = self._recompute_tx(
                    self.conn, notice["order_no"], actor, "notice_expired")
            expired.append({"notice": notice, "recommendation": recommendation})
        return {"expired": expired}

    def get_recommendation(self, order_no):
        with self._lock:
            item = self._item_by_order_tx(self.conn, order_no)
            if item is None:
                raise NotFoundError("现场单号不存在")
            active = self.conn.execute(
                """SELECT * FROM recommendations WHERE order_no=? AND status='active'
                   ORDER BY id DESC LIMIT 1""", (order_no,)).fetchone()
            history = self.conn.execute(
                "SELECT * FROM recommendations WHERE order_no=? ORDER BY id DESC LIMIT 20",
                (order_no,)).fetchall()
        return {"active": dict(active) if active else None,
                "history": [dict(r) for r in history]}

    def close(self) -> None:
        with self._lock:
            self.conn.close()

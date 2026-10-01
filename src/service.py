from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, ValidationError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, DRAFT_ROLES, ENTITY, NOTICE_ROLES,
                    ORDER_KINDS, RECORD_ROLES, TITLE, VIEW_ROLES, completion_blockers,
                    escalation_required, priority_score, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    # ---------- 限行链：按现场单号登记告警/核查/通告 ----------

    def register_alert(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        order_no = require_text(payload.get("order_no"), "order_no", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        request_no = require_text(payload.get("request_no"), "request_no", 100)
        return self.repository.register_alert(
            order_no, title, description, severity, quantity, threshold, request_no, actor)

    def register_verification(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        order_no = require_text(payload.get("order_no"), "order_no", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        request_no = require_text(payload.get("request_no"), "request_no", 100)
        return self.repository.register_record(
            order_no, "verification", detail, status, external_ref, None,
            {"detail": detail, "status": status, "external_ref": external_ref},
            request_no, actor)

    def register_notice(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_ROLES)
        actor = require_text(actor, "actor", 100)
        order_no = require_text(payload.get("order_no"), "order_no", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        valid_until = payload.get("valid_until")
        if valid_until is not None:
            valid_until = require_text(valid_until, "valid_until", 100)
        request_no = require_text(payload.get("request_no"), "request_no", 100)
        return self.repository.register_record(
            order_no, "notice", detail, status, external_ref, valid_until,
            {"detail": detail, "status": status, "external_ref": external_ref,
             "valid_until": valid_until},
            request_no, actor)

    def update_monitoring(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        order_no = require_text(payload.get("order_no"), "order_no", 100)
        quantity = require_number(payload.get("quantity"), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        severity = normalize_severity(payload.get("severity"))
        expected_version = payload.get("expected_version")
        if expected_version is not None and (
                not isinstance(expected_version, int) or expected_version < 1):
            raise ValueError("expected_version必须是正整数")
        request_no = require_text(payload.get("request_no"), "request_no", 100)
        return self.repository.update_monitoring(
            order_no, quantity, threshold, severity, expected_version, request_no, actor)

    # ---------- 断网草稿与回网合并 ----------

    def save_draft(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, DRAFT_ROLES)
        actor = require_text(actor, "actor", 100)
        request_no = require_text(payload.get("request_no"), "request_no", 100)
        order_no = require_text(payload.get("order_no"), "order_no", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        if kind not in ORDER_KINDS:
            raise ValidationError("kind必须是alert/verification/notice")
        draft_payload = payload.get("payload")
        if not isinstance(draft_payload, dict):
            raise ValidationError("payload必须是JSON对象")
        base_hash = payload.get("base_hash")
        if base_hash is not None:
            base_hash = require_text(base_hash, "base_hash", 200)
        return self.repository.save_draft(
            request_no, order_no, kind, draft_payload, base_hash, actor)

    def list_drafts(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return self.repository.list_drafts(status)

    def merge_drafts(self, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, DRAFT_ROLES)
        actor = require_text(actor, "actor", 100)
        return self.repository.merge_drafts(actor)

    def resolve_pending(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_ROLES)
        actor = require_text(actor, "actor", 100)
        draft_id = payload.get("draft_id")
        if not isinstance(draft_id, int) or draft_id < 1:
            raise ValidationError("draft_id必须是正整数")
        keep = require_text(payload.get("keep"), "keep", 20)
        if keep not in ("center", "local"):
            raise ValidationError("keep必须是center或local")
        return self.repository.resolve_pending(draft_id, keep, actor)

    # ---------- 限行建议失效重算与通告失效 ----------

    def check_expired_notices(self, actor: str, role: str) -> Dict[str, Any]:
        self._view(role)
        actor = require_text(actor, "actor", 100)
        return self.repository.check_expired_notices(actor)

    def get_recommendation(self, order_no: str, role: str) -> Dict[str, Any]:
        self._view(role)
        order_no = require_text(order_no, "order_no", 100)
        return self.repository.get_recommendation(order_no)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result

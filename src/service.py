from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from .domain import (ConflictError, NotFoundError, ensure_role,
                     normalize_severity, parse_valid_until, require_number,
                     require_status, require_text)
from .local_draft import LocalDraftStore
from .repository import Repository
from .rules import (ALARM_KIND, ALARM_ROLES, AUDIT_ROLES, CONFLICT_ROLES,
                    CREATE_ROLES, ENTITY, INSPECTION_KIND, INSPECTION_ROLES,
                    INSPECTION_STATUS_CLOSED, INSPECTION_STATUS_OPEN,
                    INSPECTION_STATUS_REOPENED, MEASUREMENT_ROLES, NOTICE_KIND,
                    NOTICE_ROLES, NOTICE_STATUS_ACTIVE, NOTICE_STATUS_EXPIRED,
                    RECORD_ROLES, RECORD_STATUS_CLOSED, RECORD_STATUS_OPEN,
                    TITLE, VIEW_ROLES, calculate_recommendation,
                    completion_blockers, escalation_required,
                    priority_score, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository,
                 draft_store: Optional[LocalDraftStore] = None):
        self.repository = repository
        self.draft_store = draft_store or LocalDraftStore(None)

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def _fingerprint(self, operation: str, payload: Dict[str, Any]) -> str:
        raw = json.dumps(
            {'operation': operation, 'payload': payload},
            ensure_ascii=False, sort_keys=True, default=str,
        ).encode('utf-8')
        return hashlib.sha256(raw).hexdigest()

    def _request_id(self, payload: Optional[Dict[str, Any]] = None) -> Optional[str]:
        if payload is None:
            return None
        value = payload.get('request_id')
        if value is None:
            return None
        return require_text(value, 'request_id', 120)

    def _idempotently(self, request_id: Optional[str], operation: str,
                      payload: Dict[str, Any], fn) -> Dict[str, Any]:
        if not request_id:
            return fn()
        fingerprint = self._fingerprint(operation, payload)
        existing = self.repository.get_processed_request(request_id)
        if existing:
            if existing['fingerprint'] != fingerprint:
                raise ConflictError('请求编号已用于不同请求，请使用新编号')
            return dict(existing['response'])
        with self.repository.transaction():
            response = fn()
            self.repository.save_processed_request(request_id, operation,
                                                   fingerprint, response)
        return response

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
        request_id = self._request_id(payload)

        def create():
            item = self.repository.create_item(title, description, severity, quantity,
                                               threshold, external_ref, actor)
            self.repository.append_audit("create", ENTITY, item["id"], actor, {
                "title": title, "severity": severity, "quantity": quantity,
                "priority": priority_score(severity, quantity, threshold),
                "request_id": request_id,
            })
            result = self.enrich(item)
            self._refresh_recommendation(item["id"], actor, "新建桥梁告警")
            return result

        return self._idempotently(request_id, 'create_item', payload, create)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in (RECORD_STATUS_OPEN, RECORD_STATUS_CLOSED):
            _validation("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        valid_until = parse_valid_until(payload.get("valid_until"))
        request_id = self._request_id(payload)

        def add():
            record = self.repository.add_record(item_id, kind, detail, status,
                                                external_ref, actor, 'center',
                                                valid_until)
            self.repository.append_audit("record", ENTITY, item_id, actor, {
                "record_id": record["id"], "kind": kind, "status": status,
                "request_id": request_id,
            })
            self._refresh_recommendation(item_id, actor, f"新增{kind}记录")
            return record

        return self._idempotently(request_id, 'add_record', payload, add)

    def register_case(self, payload: Dict[str, Any], actor: str,
                      role: str, source: str = 'center',
                      create_item_allowed: Optional[bool] = None) -> Dict[str, Any]:
        """值班员按同一个现场单号登记三类分离的记录。"""
        ensure_role(role, {'duty_officer'})
        actor = require_text(actor, 'actor', 100)
        ticket_no = require_text(payload.get('ticket_no'), 'ticket_no', 100)
        request_id = require_text(self._request_id(payload), 'request_id', 120)
        sections = self._validate_case_sections(payload, ticket_no)
        request_payload = dict(payload)
        if request_id:
            request_payload['request_id'] = request_id

        allowed = create_item_allowed if create_item_allowed is not None else source == 'center'

        def register():
            return self._register_case_txn(
                ticket_no, sections, request_id, actor, source, allowed
            )

        return self._idempotently(request_id, 'register_case', request_payload, register)

    def _validate_case_sections(self, payload: Dict[str, Any],
                                ticket_no: str) -> Dict[str, Dict[str, Any]]:
        raw_sections = payload.get('sections')
        if not isinstance(raw_sections, dict):
            _validation('sections必须是对象')
        allowed = {
            ALARM_KIND: ALARM_ROLES,
            INSPECTION_KIND: INSPECTION_ROLES,
            NOTICE_KIND: NOTICE_ROLES,
        }
        result = {}
        for kind in allowed:
            if kind not in raw_sections:
                continue
            section = raw_sections[kind]
            if not isinstance(section, dict):
                _validation(f'{kind}必须是对象')
            operation = section.get('operation', 'create')
            if operation not in ('create', 'update'):
                _validation(f'{kind}.operation必须是create或update')
            if operation == 'update':
                has_base = section.get('base_version') is not None or \
                    section.get('base_updated_at') is not None
                if not has_base:
                    _validation(f'{kind}.update必须提供base_version或base_updated_at')
            detail = require_text(section.get('detail'), f'{kind}.detail')
            number = section.get('number') or f'{ticket_no}-{kind.upper()}'
            number = require_text(number, f'{kind}.number', 100)
            value = {
                'operation': operation,
                'detail': detail,
                'number': number,
                'base_version': section.get('base_version'),
                'base_updated_at': section.get('base_updated_at'),
                'valid_until': parse_valid_until(section.get('valid_until')),
            }
            if kind == ALARM_KIND:
                value['severity'] = normalize_severity(
                    section.get('severity', 'warning'))
                value['quantity'] = require_number(
                    section.get('quantity', 0), f'{kind}.quantity')
                value['threshold'] = require_number(
                    section.get('threshold', 1), f'{kind}.threshold', 0.000001)
                value['status'] = RECORD_STATUS_OPEN
            elif kind == INSPECTION_KIND:
                value['status'] = require_status(
                    section.get('status', INSPECTION_STATUS_OPEN),
                    f'{kind}.status',
                    (INSPECTION_STATUS_OPEN, INSPECTION_STATUS_CLOSED,
                     INSPECTION_STATUS_REOPENED),
                )
            else:
                value['status'] = require_status(
                    section.get('status', NOTICE_STATUS_ACTIVE),
                    f'{kind}.status',
                    (NOTICE_STATUS_ACTIVE, NOTICE_STATUS_EXPIRED),
                )
            result[kind] = value
        if not result:
            _validation('至少登记告警、现场核查或交通通告中的一项')
        return result

    def _register_case_txn(self, ticket_no: str,
                           sections: Dict[str, Dict[str, Any]],
                           request_id: Optional[str], actor: str,
                           source: str, create_item_allowed: bool) -> Dict[str, Any]:
        conflicts = []
        item = self.repository.get_item_by_external_ref(ticket_no)
        base_version = self._case_base_version(sections)
        if item is None:
            if not create_item_allowed:
                conflict = self.repository.create_conflict(
                    ticket_no, None, request_id,
                    {'ticket_no': ticket_no, 'item': None, 'records': []},
                    {'ticket_no': ticket_no, 'sections': sections}, actor,
                )
                self.repository.append_audit(
                    'merge_conflict', '限行链', 0, actor,
                    {'request_id': request_id, 'conflict_id': conflict['id'],
                     'fields': ['item'], 'center_notice_preserved': True},
                )
                return {'status': 'conflicted', 'conflict': conflict,
                        'conflicts': [{'field': 'item',
                                       'reason': '本地草稿引用的现场单号在中心不存在'}],
                        'item': None}
            item = self._create_case_item(ticket_no, sections, actor)
        elif source == 'offline' and base_version is not None and \
                item['version'] != base_version:
            conflicts.append({
                'field': 'item',
                'reason': '同一现场单号中心版本已变化',
                'center': {'version': item['version']},
                'local': {'base_version': base_version},
            })

        planned_records = []
        for kind, section in sections.items():
            existing = self.repository.find_record(item['id'], kind, section['number'])
            center_copy, local_copy, conflict = self._section_conflict(
                item, existing, kind, section
            )
            if conflict:
                conflicts.append({
                    'field': kind,
                    'reason': conflict,
                    'center': center_copy,
                    'local': local_copy,
                })
            else:
                planned_records.append((kind, section, existing))

        if conflicts:
            center_snapshot = self._case_snapshot(ticket_no, item)
            conflict = self.repository.create_conflict(
                ticket_no, item['id'], request_id, center_snapshot,
                {'ticket_no': ticket_no, 'sections': sections}, actor,
            )
            self.repository.append_audit(
                'merge_conflict', '限行链', item['id'], actor,
                {'request_id': request_id, 'conflict_id': conflict['id'],
                 'fields': [c['field'] for c in conflicts],
                 'center_notice_preserved': True},
            )
            return {'status': 'conflicted', 'conflict': conflict,
                    'conflicts': conflicts, 'item': item}

        record_results = []
        for kind, section, existing in planned_records:
            if existing is None:
                record = self.repository.add_record(
                    item['id'], kind, section['detail'], section['status'],
                    section['number'], actor, source, section.get('valid_until'),
                )
                record['case_operation'] = 'insert'
            else:
                record = self.repository.update_record(
                    existing['id'], detail=section['detail'],
                    status=section['status'], valid_until=section.get('valid_until'),
                )
                record['case_operation'] = 'update'
            record_results.append(record)

        if ALARM_KIND in sections:
            alarm = sections[ALARM_KIND]
            item = self.repository.update_measurement(
                item['id'], alarm['severity'], alarm['quantity'],
                alarm['threshold'], item['version'], actor,
            )
        for record in record_results:
            operation_name = record.pop('case_operation', 'insert')
            self.repository.append_audit(
                f'case_record_{operation_name}', ENTITY, item['id'], actor,
                {'record_id': record['id'], 'kind': record['kind'],
                 'number': record['external_ref'], 'source': source,
                 'request_id': request_id},
            )
        self.repository.append_audit(
            'register_case', ENTITY, item['id'], actor,
            {'ticket_no': ticket_no, 'request_id': request_id, 'source': source,
             'sections': list(sections)},
        )
        self._refresh_recommendation(
            item['id'], actor, '告警、核查或通告合并登记'
        )
        return {
            'status': 'applied', 'ticket_no': ticket_no, 'item': self.enrich(item),
            'records': record_results, 'request_id': request_id,
        }

    @staticmethod
    def _case_base_version(sections):
        values = [s.get('base_version') for s in sections.values()]
        values = [v for v in values if v is not None]
        if not values:
            return None
        if any(not isinstance(v, int) or isinstance(v, bool) or v < 1 for v in values):
            _validation('base_version必须是正整数')
        return values[0]

    def _create_case_item(self, ticket_no, sections, actor):
        alarm = sections.get(ALARM_KIND)
        severity = alarm['severity'] if alarm else 'warning'
        quantity = alarm['quantity'] if alarm else 0
        threshold = alarm['threshold'] if alarm else 1
        return self.repository.create_item(
            f'现场单号 {ticket_no}', '值班员按现场单号登记', severity,
            quantity, threshold, ticket_no, actor,
        )

    def _section_conflict(self, item, existing, kind, section):
        local_copy = {
            'number': section['number'],
            'status': section['status'],
            'detail': section['detail'],
            'valid_until': section.get('valid_until'),
            'base_version': section.get('base_version'),
            'base_updated_at': section.get('base_updated_at'),
        }
        if existing is None:
            if section['operation'] == 'update':
                return None, local_copy, '本地更新的记录在中心不存在'
            return None, local_copy, None
        center_copy = {
            'number': existing.get('external_ref'),
            'status': existing.get('status'),
            'detail': existing.get('detail'),
            'valid_until': existing.get('valid_until'),
            'updated_at': existing.get('updated_at'),
        }
        if kind == NOTICE_KIND:
            return center_copy, local_copy, '交通通告中心版本不得被断网草稿覆盖'
        if section['operation'] == 'create':
            return center_copy, local_copy, '同单号同类型记录中心已存在'
        base_version = section.get('base_version')
        base_updated_at = section.get('base_updated_at')
        if base_version is not None:
            if not isinstance(base_version, int) or isinstance(base_version, bool) \
                    or base_version < 1:
                _validation('base_version必须是正整数')
            if base_version != item['version']:
                return center_copy, local_copy, '同单号两边都改过：桥梁版本不一致'
        if base_updated_at is not None and base_updated_at != existing.get('updated_at'):
            return center_copy, local_copy, '同单号两边都改过：记录更新时间不一致'
        return center_copy, local_copy, None

    def _case_snapshot(self, ticket_no, item):
        if item is None:
            return {'ticket_no': ticket_no, 'item': None, 'records': []}
        return {'ticket_no': ticket_no, 'item': item,
                'records': self.repository.list_records(item['id'])}

    def update_measurement(self, item_id: int, payload: Dict[str, Any],
                           actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, MEASUREMENT_ROLES)
        actor = require_text(actor, 'actor', 100)
        expected = payload.get('expected_version')
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
            _validation('expected_version必须是正整数')
        severity = payload.get('severity')
        if severity is not None:
            severity = normalize_severity(severity)
        quantity = payload.get('quantity')
        if quantity is not None:
            quantity = require_number(quantity, 'quantity')
        threshold = payload.get('threshold')
        if threshold is not None:
            threshold = require_number(threshold, 'threshold', 0.000001)
        if severity is None and quantity is None and threshold is None:
            _validation('至少提交severity、quantity或threshold中的一项')
        request_id = self._request_id(payload)

        def update():
            updated = self.repository.update_measurement(
                item_id, severity, quantity, threshold, expected, actor
            )
            self.repository.append_audit(
                'measurement_changed', ENTITY, item_id, actor,
                {'severity': updated['severity'], 'quantity': updated['quantity'],
                 'threshold': updated['threshold'], 'version': updated['version'],
                 'request_id': request_id},
            )
            self._refresh_recommendation(item_id, actor, '监测值变化')
            return self.enrich(updated)

        return self._idempotently(request_id, 'update_measurement', payload, update)

    def reopen_inspection(self, record_id: int, payload: Dict[str, Any],
                         actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, INSPECTION_ROLES)
        actor = require_text(actor, 'actor', 100)
        record = self.repository.get_record(record_id)
        if record['kind'] != INSPECTION_KIND:
            _validation('只有现场核查可以重开')
        detail = payload.get('detail', record['detail'])
        detail = require_text(detail, 'detail')
        request_id = self._request_id(payload)

        def reopen():
            updated = self.repository.update_record(
                record_id, status=INSPECTION_STATUS_REOPENED, detail=detail,
            )
            self.repository.append_audit(
                'inspection_reopened', ENTITY, updated['item_id'], actor,
                {'record_id': record_id, 'detail': detail,
                 'request_id': request_id},
            )
            self._refresh_recommendation(updated['item_id'], actor, '现场核查重开')
            return updated

        return self._idempotently(request_id, 'reopen_inspection', payload, reopen)

    def expire_notice(self, record_id: int, payload: Dict[str, Any],
                      actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_ROLES)
        actor = require_text(actor, 'actor', 100)
        record = self.repository.get_record(record_id)
        if record['kind'] != NOTICE_KIND:
            _validation('只有交通通告可以失效')
        request_id = self._request_id(payload)

        def expire():
            updated = self.repository.update_record(
                record_id, status=NOTICE_STATUS_EXPIRED
            )
            self.repository.append_audit(
                'notice_expired', ENTITY, updated['item_id'], actor,
                {'record_id': record_id, 'number': updated['external_ref'],
                 'request_id': request_id},
            )
            self._refresh_recommendation(updated['item_id'], actor, '交通通告失效')
            return updated

        return self._idempotently(request_id, 'expire_notice', payload, expire)

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
        with self.repository.transaction():
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

    def recommendation(self, item_id: int, role: str,
                       refresh_expired: bool = True) -> Dict[str, Any]:
        self._view(role)
        item = self.repository.get_item(item_id)
        if refresh_expired:
            self._expire_notices_and_refresh(item_id, 'system')
        active = self.repository.get_active_recommendation(item_id)
        if active is None:
            active = self._refresh_recommendation(item_id, 'system', '补算限行建议')
        records = self.repository.list_records(item_id)
        current = calculate_recommendation(item, records)
        active['current'] = current
        active['valid'] = active.get('basis_hash') == current['basis_hash']
        return active

    def list_recommendations(self, item_id: Optional[int], role: str) -> list:
        self._view(role)
        return self.repository.list_recommendations(item_id)

    def list_conflicts(self, role: str, status: Optional[str] = None) -> list:
        ensure_role(role, CONFLICT_ROLES)
        return self.repository.list_conflicts(status)

    def resolve_conflict(self, conflict_id: int, payload: Dict[str, Any],
                         actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CONFLICT_ROLES)
        actor = require_text(actor, 'actor', 100)
        resolution = require_text(payload.get('resolution'), 'resolution', 100)
        if resolution not in ('keep_center', 'apply_local', 'manual_merge'):
            _validation('resolution必须是keep_center、apply_local或manual_merge')
        request_id = self._request_id(payload)

        def resolve():
            conflict = self.repository.resolve_conflict(conflict_id, resolution, actor)
            self.repository.append_audit(
                'conflict_resolved', '限行链', conflict['item_id'] or 0, actor,
                {'conflict_id': conflict_id, 'resolution': resolution,
                 'request_id': request_id,
                 'center_notice_preserved': resolution == 'keep_center'},
            )
            return conflict

        clean = {k: v for k, v in payload.items() if k != 'request_id'}
        return self._idempotently(request_id, 'resolve_conflict', clean, resolve)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    def save_draft(self, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        actor = require_text(actor, 'actor', 100)
        require_text(role, 'role', 100)
        request_id = require_text(self._request_id(payload), 'request_id', 120)
        operation = require_text(payload.get('operation'), 'operation', 100)
        if operation not in ('register_case', 'update_measurement',
                             'reopen_inspection', 'expire_notice'):
            _validation('不支持的草稿操作')
        request_payload = payload.get('payload')
        if not isinstance(request_payload, dict):
            _validation('payload必须是对象')
        request_payload = dict(request_payload)
        request_payload['request_id'] = request_id
        self._validate_draft_shape(operation, request_payload)
        try:
            existing = self.draft_store.get(request_id)
        except NotFoundError:
            existing = None
        if existing is not None and existing.get('status') in (
                'pending', 'retrying', 'conflicted') and (
                existing.get('operation') != operation
                or existing.get('payload') != request_payload):
            raise ConflictError('请求编号已有不同草稿；请使用原编号或新编号')
        draft = self.draft_store.save(
            request_id, operation, request_payload, actor, role
        )
        return self._draft_view(draft)

    def _validate_draft_shape(self, operation, payload):
        """断网保存只做可在本地完成的形状校验，不读取中心状态。"""
        if operation == 'register_case':
            ticket_no = require_text(payload.get('ticket_no'), 'ticket_no', 100)
            self._validate_case_sections(payload, ticket_no)
            return
        if operation == 'update_measurement':
            require_text(payload.get('ticket_no'), 'ticket_no', 100)
            expected = payload.get('expected_version')
            if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
                _validation('expected_version必须是正整数')
            quantity = payload.get('quantity')
            severity = payload.get('severity')
            threshold = payload.get('threshold')
            if quantity is not None:
                require_number(quantity, 'quantity')
            if severity is not None:
                normalize_severity(severity)
            if threshold is not None:
                require_number(threshold, 'threshold', 0.000001)
            return
        record_id = payload.get('record_id')
        if not isinstance(record_id, int) or isinstance(record_id, bool) or record_id < 1:
            _validation('record_id必须是正整数')

    def list_drafts(self, role: str) -> List[Dict[str, Any]]:
        self._view(role)
        return [self._draft_view(d) for d in self.draft_store.list_pending()]

    def get_draft(self, request_id: str, role: str) -> Dict[str, Any]:
        self._view(role)
        return self._draft_view(self.draft_store.get(request_id))

    def retry_draft(self, request_id: str, role: str) -> Dict[str, Any]:
        self._view(role)
        draft = self.draft_store.get(request_id)
        return self._sync_one(draft, preserve_on_failure=True)

    def sync_drafts(self, role: str) -> Dict[str, Any]:
        self._view(role)
        results = []
        for draft in self.draft_store.list_pending():
            results.append(self._sync_one(draft, preserve_on_failure=True))
        return {'results': results}

    def _sync_one(self, draft: Dict[str, Any], preserve_on_failure: bool) -> Dict[str, Any]:
        request_id = draft['request_id']
        self.draft_store.mark(request_id, 'retrying', attempts=draft.get('attempts', 0) + 1)
        try:
            response = self._dispatch_draft(draft)
        except ConflictError as exc:
            # 冲突不是写入失败：原草稿继续保留，中心另存两份待确认。
            refreshed = self.draft_store.get(request_id)
            return {'request_id': request_id, 'status': 'conflicted',
                    'draft_retained': True, 'error': str(exc),
                    'response': _conflict_from_error(exc)}
        except Exception as exc:
            if preserve_on_failure:
                self.draft_store.mark(
                    request_id, 'pending',
                    last_error=f'{exc.__class__.__name__}: {exc}',
                    attempts=draft.get('attempts', 0) + 1,
                )
            return {'request_id': request_id, 'status': 'retry_pending',
                    'draft_retained': True, 'error': str(exc)}
        status = response.get('status', 'applied')
        if status == 'conflicted':
            self.draft_store.mark(
                request_id, 'conflicted', result=response,
                last_error='同单号两边都改过，中心已保留两份待确认',
            )
            return {'request_id': request_id, 'status': 'conflicted',
                    'draft_retained': True, 'response': response}
        self.draft_store.mark(request_id, 'applied', result=response)
        return {'request_id': request_id, 'status': 'applied',
                'response': response}

    def _dispatch_draft(self, draft):
        payload = dict(draft['payload'])
        payload['request_id'] = draft['request_id']
        actor, role = draft['actor'], draft['role']
        if draft['operation'] == 'register_case':
            return self.register_case(payload, actor, role, 'offline', False)
        if draft['operation'] == 'update_measurement':
            item = self.repository.get_item_by_external_ref(
                require_text(payload.get('ticket_no'), 'ticket_no', 100)
            )
            return self.update_measurement(item['id'], payload, actor, role)
        if draft['operation'] == 'reopen_inspection':
            return self.reopen_inspection(payload['record_id'], payload, actor, role)
        if draft['operation'] == 'expire_notice':
            return self.expire_notice(payload['record_id'], payload, actor, role)
        raise ConflictError('不支持的草稿操作')

    @staticmethod
    def _draft_view(draft):
        view = dict(draft)
        view['draft_retained'] = view.get('status') in ('pending', 'retrying', 'conflicted')
        return view

    def _expire_notices_and_refresh(self, item_id, actor):
        expired = self.repository.expire_active_notices(item_id)
        if expired:
            for record in expired:
                self.repository.append_audit(
                    'notice_expired', ENTITY, item_id, actor,
                    {'record_id': record['id'], 'number': record['external_ref'],
                     'reason': 'valid_until到期'},
                )
            self._refresh_recommendation(item_id, actor, '交通通告到期失效')

    def _refresh_recommendation(self, item_id: int, actor: str,
                                reason: str) -> Dict[str, Any]:
        item = self.repository.get_item(item_id)
        records = self.repository.list_records(item_id)
        calculation = calculate_recommendation(item, records)
        active = self.repository.get_active_recommendation(item_id)
        if active and active.get('basis_hash') == calculation['basis_hash']:
            return active
        if active:
            self.repository.append_audit(
                'recommendation_invalidated', '限行建议', item_id, actor,
                {'previous_id': active['id'], 'reason': reason,
                 'previous_basis_hash': active['basis_hash']},
            )
        saved = self.repository.replace_recommendation(item_id, calculation, actor)
        self.repository.append_audit(
            'recommendation_calculated', '限行建议', item_id, actor,
            {'recommendation_id': saved.get('id'), 'advice': saved.get('advice'),
             'reason': calculation['reason'], 'basis_hash': calculation['basis_hash'],
             'trigger': reason},
        )
        return self.repository.get_active_recommendation(item_id)

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


def _validation(message: str):
    from .domain import ValidationError
    raise ValidationError(message)


def _conflict_from_error(exc):
    return {'error': exc.__class__.__name__, 'message': str(exc)}

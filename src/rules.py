from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .domain import ConflictError, ValidationError

TITLE = '桥梁结构监测与限行决策'
ENTITY = '桥梁告警'
ID_PREFIX = 'BM'
SEVERITIES = ['normal', 'watch', 'warning', 'critical']
STATES = ['normal', 'warning', 'restricted', 'closed', 'restored']
TRANSITIONS = {
    'normal': ['warning'],
    'warning': ['restricted'],
    'restricted': ['closed'],
    'closed': ['restored'],
    'restored': [],
}
TRANSITION_ROLES = {
    'warning': ['sensor_operator'],
    'restricted': ['bridge_engineer'],
    'closed': ['traffic_authority'],
    'restored': ['bridge_engineer'],
}

CREATE_ROLES = {'sensor_operator'}
RECORD_ROLES = {
    'sensor_operator', 'bridge_engineer', 'traffic_authority', 'duty_officer',
}
ALARM_ROLES = {'sensor_operator', 'duty_officer'}
INSPECTION_ROLES = {'bridge_engineer', 'duty_officer'}
NOTICE_ROLES = {'traffic_authority', 'duty_officer'}
MEASUREMENT_ROLES = {'sensor_operator', 'duty_officer'}
AUDIT_ROLES = {'bridge_engineer', 'viewer', 'duty_officer', 'traffic_authority'}
VIEW_ROLES = {
    'sensor_operator', 'bridge_engineer', 'traffic_authority',
    'duty_officer', 'viewer',
}
CONFLICT_ROLES = {'bridge_engineer', 'traffic_authority', 'duty_officer'}

ALARM_KIND = 'alarm'
INSPECTION_KIND = 'inspection'
NOTICE_KIND = 'traffic_notice'
CASE_RECORD_KINDS = (ALARM_KIND, INSPECTION_KIND, NOTICE_KIND)
RECORD_STATUS_OPEN = 'open'
RECORD_STATUS_CLOSED = 'closed'
NOTICE_STATUS_ACTIVE = 'active'
NOTICE_STATUS_EXPIRED = 'expired'
INSPECTION_STATUS_OPEN = 'open'
INSPECTION_STATUS_CLOSED = 'closed'
INSPECTION_STATUS_REOPENED = 'reopened'

SEVERITY_WEIGHT = {'normal': 1.0, 'watch': 3.0, 'warning': 6.0, 'critical': 9.0}
DEADLINE_HOURS = {'normal': 72, 'watch': 24, 'warning': 8, 'critical': 4}
TERMINAL_STATES = {'restored'}


def priority_score(severity, quantity=0.0, threshold=1.0, open_records=0):
    if severity not in SEVERITY_WEIGHT:
        raise ValidationError("unknown severity")
    ratio = quantity / threshold if threshold > 0 else 1.0
    return max(0, min(10, int(round(
        SEVERITY_WEIGHT[severity]
        + min(4.0, ratio * 4.0)
        + min(3.0, float(open_records))
    ))))


def response_deadline_hours(severity, quantity=0.0, threshold=1.0):
    if severity not in DEADLINE_HOURS:
        raise ValidationError("unknown severity")
    ratio = quantity / threshold if threshold > 0 else 1.0
    return max(1, int(DEADLINE_HOURS[severity] / max(1.0, ratio)))


def escalation_required(severity, quantity=0.0, threshold=1.0):
    return severity == SEVERITIES[-1] or (threshold > 0 and quantity >= threshold)


def can_transition(current, target):
    return target in TRANSITIONS.get(current, [])


def validate_transition(current, target):
    if current not in STATES or target not in STATES:
        raise ValidationError("未知状态")
    if not can_transition(current, target):
        raise ConflictError(f"不能从{current}转换到{target}")


def completion_blockers(target, open_records):
    return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records > 0 else []


def role_for_transition(target):
    return set(TRANSITION_ROLES.get(target, []))


def now_utc():
    return datetime.now(timezone.utc)


def notice_is_active(record, at=None):
    if record["kind"] != NOTICE_KIND or record.get("status") != NOTICE_STATUS_ACTIVE:
        return False
    valid_until = record.get("valid_until")
    if not valid_until:
        return True
    moment = at or now_utc()
    try:
        end = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    except ValueError:
        return False
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return end > moment.astimezone(timezone.utc)


def calculate_recommendation(item, records, at=None):
    """根据告警、现场核查和交通通告三类事实计算限行建议。"""
    open_inspections = [
        r for r in records
        if r.get("kind") == INSPECTION_KIND
        and r.get("status") in (INSPECTION_STATUS_OPEN, INSPECTION_STATUS_REOPENED)
    ]
    active_notices = [r for r in records if notice_is_active(r, at)]
    latest_alarm = None
    for r in records:
        if r.get("kind") == ALARM_KIND:
            latest_alarm = r
    danger = escalation_required(
        item["severity"], item["quantity"], item["threshold"]
    )

    if not active_notices:
        advice = 'monitor'
        reason = '没有有效交通通告，不形成限行'
    elif danger:
        advice = 'restrict'
        reason = '监测值达到或超过阈值，或告警为critical'
    elif open_inspections:
        advice = 'restrict'
        reason = '现场核查未关闭或已重开'
    else:
        advice = 'normal'
        reason = '通告有效，监测值与核查均正常'

    basis = {
        'severity': item['severity'],
        'quantity': item['quantity'],
        'threshold': item['threshold'],
        'version': item['version'],
        'alarm_updated_at': latest_alarm.get('updated_at') if latest_alarm else None,
        'inspections': sorted(
            {r.get('status') for r in records if r.get('kind') == INSPECTION_KIND}
        ),
        'active_notice_ids': sorted(r['id'] for r in active_notices),
        'records_hash_version': hashlib.sha256(json.dumps(
            _record_basis(records), ensure_ascii=False, sort_keys=True
        ).encode('utf-8')).hexdigest(),
    }
    basis_hash = hashlib.sha256(json.dumps(
        basis, ensure_ascii=False, sort_keys=True, default=str
    ).encode('utf-8')).hexdigest()
    return {
        'advice': advice,
        'reason': reason,
        'basis': basis,
        'basis_hash': basis_hash,
        'restriction_active': advice == 'restrict',
    }


def _record_basis(records):
    return [
        {
            'id': r['id'],
            'kind': r['kind'],
            'status': r['status'],
            'detail': r.get('detail'),
            'external_ref': r.get('external_ref'),
            'valid_until': r.get('valid_until'),
            'updated_at': r.get('updated_at'),
        }
        for r in sorted(records, key=lambda r: r['id'])
    ]

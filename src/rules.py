from __future__ import annotations
from .domain import ConflictError, ValidationError
TITLE='桥梁结构监测与限行决策'; ENTITY='桥梁告警'; ID_PREFIX='BM'
SEVERITIES=['normal', 'watch', 'warning', 'critical']; STATES=['normal', 'warning', 'restricted', 'closed', 'restored']; TRANSITIONS={'normal': ['warning'], 'warning': ['restricted'], 'restricted': ['closed'], 'closed': ['restored'], 'restored': []}; TRANSITION_ROLES={'warning': ['sensor_operator'], 'restricted': ['bridge_engineer'], 'closed': ['traffic_authority'], 'restored': ['bridge_engineer']}
CREATE_ROLES=set(['sensor_operator']); RECORD_ROLES=set(['sensor_operator', 'bridge_engineer']); AUDIT_ROLES=set(['bridge_engineer', 'viewer']); VIEW_ROLES=set(['sensor_operator', 'bridge_engineer', 'traffic_authority', 'viewer'])
NOTICE_ROLES=set(['bridge_engineer', 'traffic_authority']); DRAFT_ROLES=set(['sensor_operator', 'bridge_engineer', 'traffic_authority'])
SEVERITY_WEIGHT={'normal': 1.0, 'watch': 3.0, 'warning': 6.0, 'critical': 9.0}; DEADLINE_HOURS={'normal': 72, 'watch': 24, 'warning': 8, 'critical': 4}; TERMINAL_STATES=set(['restored'])
ORDER_KINDS=['alert', 'verification', 'notice']; DRAFT_STATUSES=['draft', 'merged', 'pending_confirmation']; RECOMMENDATION_LEVELS=['normal', 'advisory', 'restricted', 'closed']
def priority_score(severity,quantity=0.0,threshold=1.0,open_records=0):
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(0,min(10,int(round(SEVERITY_WEIGHT[severity]+min(4.0,ratio*4.0)+min(3.0,float(open_records))))))
def response_deadline_hours(severity,quantity=0.0,threshold=1.0):
    if severity not in DEADLINE_HOURS: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(1,int(DEADLINE_HOURS[severity]/max(1.0,ratio)))
def escalation_required(severity,quantity=0.0,threshold=1.0):
    return severity==SEVERITIES[-1] or (threshold>0 and quantity>=threshold)
def can_transition(current,target): return target in TRANSITIONS.get(current,[])
def validate_transition(current,target):
    if current not in STATES or target not in STATES: raise ValidationError("未知状态")
    if not can_transition(current,target): raise ConflictError(f"不能从{current}转换到{target}")
def completion_blockers(target,open_records): return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records>0 else []
def role_for_transition(target): return set(TRANSITION_ROLES.get(target,[]))
def compute_recommendation(severity,quantity=0.0,threshold=1.0,verification_open=False,valid_notice=False):
    """根据告警、核查与通告状态计算限行建议级别及原因。

    核查未完成/重开或通告缺失/失效时，限行建议不得维持，降为 advisory。
    """
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    if severity=='critical' or ratio>=3.0:
        base='closed'
    elif severity=='warning' or ratio>=1.0:
        base='restricted'
    elif severity=='watch':
        base='advisory'
    else:
        base='normal'
    reasons=[]
    if base in ('restricted','closed'):
        if verification_open:
            reasons.append('核查未完成或已重开')
            base='advisory'
        elif not valid_notice:
            reasons.append('交通通告缺失或已失效')
            base='advisory'
    if not reasons:
        if base=='normal':
            reasons.append('监测正常')
        elif base=='advisory':
            reasons.append('建议关注')
        else:
            reasons.append('监测超限且通告有效')
    return base,'；'.join(reasons)
def snapshot_payload(item,records):
    """现场单号当前状态的快照，用于断网草稿的三方合并比对。"""
    return {
        'severity':item['severity'],'quantity':item['quantity'],'threshold':item['threshold'],
        'version':item['version'],'updated_at':item['updated_at'],
        'records':[
            {'kind':r['kind'],'status':r['status'],'external_ref':r['external_ref'],
             'valid_until':r.get('valid_until'),'payload':r.get('payload')}
            for r in records
        ],
    }

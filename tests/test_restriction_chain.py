from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.domain import ConflictError
from src.local_draft import LocalDraftStore
from src.repository import Repository
from src.service import Service


class RestrictionChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.repo = Repository(str(root / 'center.db'))
        self.drafts = LocalDraftStore(str(root / 'drafts.json'))
        self.service = Service(self.repo, self.drafts)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def case_payload(self, request_id, ticket='SCENE-1', base=None,
                     quantity=12, threshold=10, valid_until=None):
        section_base = {} if base is None else {'base_version': base}
        payload = {
            'request_id': request_id,
            'ticket_no': ticket,
            'sections': {
                'alarm': dict({
                    'detail': '位移告警',
                    'severity': 'critical',
                    'quantity': quantity,
                    'threshold': threshold,
                }, **section_base),
                'inspection': dict({
                    'detail': '现场核查裂缝',
                    'status': 'open',
                }, **section_base),
                'traffic_notice': {
                    'detail': '现场临时交通管制',
                    'status': 'active',
                    'valid_until': valid_until,
                },
            },
        }
        return payload

    def test_separate_records_form_restriction_chain(self):
        result = self.service.register_case(
            self.case_payload('REQ-1'), 'duty', 'duty_officer'
        )
        self.assertEqual(result['status'], 'applied')
        item = result['item']
        records = self.service.list_records(item['id'], 'viewer')
        kinds = {r['kind'] for r in records}
        self.assertEqual(kinds, {'alarm', 'inspection', 'traffic_notice'})
        numbers = {r['external_ref'] for r in records}
        self.assertEqual(numbers, {'SCENE-1-ALARM', 'SCENE-1-INSPECTION', 'SCENE-1-TRAFFIC_NOTICE'})

        recommendation = self.service.recommendation(item['id'], 'viewer')
        self.assertTrue(recommendation['valid'])
        self.assertEqual(recommendation['advice'], 'restrict')

        audit_actions = {e['action'] for e in self.service.audit('viewer')}
        self.assertIn('register_case', audit_actions)
        self.assertIn('recommendation_calculated', audit_actions)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_notice_expiry_inspection_reopen_and_measurement_invalidate_advice(self):
        registered = self.service.register_case(
            self.case_payload('REQ-2', quantity=1, threshold=10), 'duty', 'duty_officer'
        )
        item_id = registered['item']['id']
        records = self.service.list_records(item_id, 'viewer')
        inspection = next(r for r in records if r['kind'] == 'inspection')
        notice = next(r for r in records if r['kind'] == 'traffic_notice')

        initial = self.service.recommendation(item_id, 'viewer')
        self.assertEqual(initial['advice'], 'restrict')

        self.service.reopen_inspection(
            inspection['id'],
            {'detail': '裂缝继续发展', 'request_id': 'REQ-REOPEN'},
            'engineer', 'bridge_engineer',
        )
        reopened = self.service.recommendation(item_id, 'viewer')
        self.assertEqual(reopened['advice'], 'restrict')
        self.assertNotEqual(reopened['id'], initial['id'])
        self.assertFalse(initial['basis_hash'] == reopened['basis_hash'])

        self.service.expire_notice(
            notice['id'], {'request_id': 'REQ-EXPIRE'},
            'traffic', 'traffic_authority',
        )
        expired_advice = self.service.recommendation(item_id, 'viewer')
        self.assertEqual(expired_advice['advice'], 'monitor')
        self.assertFalse(expired_advice['valid'] is False)

        self.service.update_measurement(
            item_id,
            {'severity': 'critical', 'quantity': 20, 'threshold': 10,
             'expected_version': registered['item']['version'],
             'request_id': 'REQ-MEASURE'},
            'operator', 'sensor_operator',
        )
        changed = self.service.recommendation(item_id, 'viewer')
        self.assertEqual(changed['advice'], 'monitor')
        actions = [e['action'] for e in self.service.audit('viewer', item_id)]
        self.assertIn('recommendation_invalidated', actions)

    def test_scheduled_notice_expiry_recomputes_on_read(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        registered = self.service.register_case(
            self.case_payload('REQ-3', quantity=1, threshold=10, valid_until=past),
            'duty', 'duty_officer',
        )
        item_id = registered['item']['id']
        first = self.service.recommendation(item_id, 'viewer')
        self.assertEqual(first['advice'], 'monitor')
        notice = next(r for r in self.service.list_records(item_id, 'viewer')
                      if r['kind'] == 'traffic_notice')
        self.assertEqual(notice['status'], 'expired')

    def test_offline_draft_syncs_and_keeps_original_request_id(self):
        registered = self.service.register_case(
            self.case_payload('REQ-4', quantity=1, threshold=10), 'duty', 'duty_officer'
        )
        item_id = registered['item']['id']
        version = registered['item']['version']

        draft = self.service.save_draft({
            'request_id': 'REQ-OFF-1',
            'operation': 'update_measurement',
            'payload': {
                'ticket_no': 'SCENE-1',
                'severity': 'critical',
                'quantity': 99,
                'threshold': 10,
                'expected_version': version,
            },
        }, 'duty', 'duty_officer')
        self.assertEqual(draft['status'], 'pending')
        self.assertTrue(draft['draft_retained'])
        self.assertEqual(draft['payload']['request_id'], 'REQ-OFF-1')

        sync = self.service.sync_drafts('duty_officer')
        self.assertEqual(sync['results'][0]['status'], 'applied')
        processed = self.repo.get_processed_request('REQ-OFF-1')
        self.assertEqual(processed['operation'], 'update_measurement')
        self.assertEqual(self.repo.get_item(item_id)['quantity'], 99)
        self.assertEqual(self.service.get_draft('REQ-OFF-1', 'viewer')['status'], 'applied')
        # 原编号重试返回同一个中心结果，不产生第二条状态变化。
        retry = self.service.retry_draft('REQ-OFF-1', 'viewer')
        self.assertEqual(retry['status'], 'applied')
        self.assertEqual(self.repo.get_item(item_id)['version'], version + 1)

    def test_same_ticket_changed_both_sides_keeps_two_copies_and_notice(self):
        registered = self.service.register_case(
            self.case_payload('REQ-5', quantity=1, threshold=10), 'duty', 'duty_officer'
        )
        item_id = registered['item']['id']
        version = registered['item']['version']

        self.service.update_measurement(
            item_id,
            {'severity': 'warning', 'quantity': 2, 'threshold': 10,
             'expected_version': version},
            'operator', 'sensor_operator',
        )

        self.service.save_draft({
            'request_id': 'REQ-CONFLICT',
            'operation': 'register_case',
            'payload': self.case_payload(
                'REQ-CONFLICT', base=version, quantity=20, threshold=10,
            ),
        }, 'duty', 'duty_officer')
        result = self.service.sync_drafts('duty_officer')['results'][0]
        self.assertEqual(result['status'], 'conflicted')
        self.assertTrue(result['draft_retained'])

        conflicts = self.service.list_conflicts('duty_officer')
        self.assertEqual(len(conflicts), 1)
        conflict = conflicts[0]
        self.assertEqual(conflict['request_id'], 'REQ-CONFLICT')
        self.assertIn('records', conflict['center_copy'])
        self.assertIn('sections', conflict['local_copy'])

        notice = next(r for r in self.service.list_records(item_id, 'viewer')
                      if r['kind'] == 'traffic_notice')
        self.assertEqual(notice['detail'], '现场临时交通管制')
        self.assertEqual(notice['status'], 'active')
        self.assertEqual(len(self.service.list_records(item_id, 'viewer')), 3)

        resolved = self.service.resolve_conflict(
            conflict['id'], {'resolution': 'keep_center', 'request_id': 'REQ-RES'},
            'chief', 'duty_officer',
        )
        self.assertEqual(resolved['status'], 'resolved')

    def test_failed_write_rolls_back_and_retry_keeps_draft(self):
        registered = self.service.register_case(
            self.case_payload('REQ-6', quantity=1, threshold=10), 'duty', 'duty_officer'
        )
        item_id = registered['item']['id']
        before = self.repo.get_item(item_id)
        self.service.save_draft({
            'request_id': 'REQ-FAIL',
            'operation': 'update_measurement',
            'payload': {
                'ticket_no': 'SCENE-1',
                'quantity': 50,
                'expected_version': before['version'],
            },
        }, 'duty', 'duty_officer')

        original = self.repo.append_audit

        def fail_audit(*args, **kwargs):
            raise RuntimeError('disk full')

        self.repo.append_audit = fail_audit
        failed = self.service.sync_drafts('duty_officer')['results'][0]
        self.repo.append_audit = original

        self.assertEqual(failed['status'], 'retry_pending')
        self.assertTrue(failed['draft_retained'])
        self.assertEqual(self.repo.get_item(item_id)['quantity'], before['quantity'])
        self.assertEqual(self.repo.get_item(item_id)['version'], before['version'])
        self.assertIsNone(self.repo.get_processed_request('REQ-FAIL'))

        retry = self.service.sync_drafts('duty_officer')['results'][0]
        self.assertEqual(retry['status'], 'applied')
        self.assertEqual(self.repo.get_item(item_id)['quantity'], 50)

    def test_request_id_rejects_changed_payload(self):
        payload = self.case_payload('REQ-SAME')
        self.service.register_case(payload, 'duty', 'duty_officer')
        changed = self.case_payload('REQ-SAME', quantity=3)
        with self.assertRaises(ConflictError):
            self.service.register_case(changed, 'duty', 'duty_officer')


if __name__ == '__main__':
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError
from src.repository import Repository
from src.service import Service


class ChainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _alert(self, order_no="BM-001", severity="warning", quantity=12, threshold=6,
               request_no="REQ-1"):
        return self.service.register_alert({
            "order_no": order_no, "title": "桥梁告警", "description": "结构监测超限",
            "severity": severity, "quantity": quantity, "threshold": threshold,
            "request_no": request_no,
        }, "officer", "sensor_operator")

    def test_register_chain_by_order_no_and_recommendation(self):
        created = self._alert()
        self.assertEqual(created["item"]["external_ref"], "BM-001")
        self.assertIsNotNone(created["recommendation"])
        # 告警 warning 但尚无有效通告 → 限行建议降为 advisory
        self.assertEqual(created["recommendation"]["level"], "advisory")

        # 补上有效通告 + 核查完成 → 限行建议升级为 restricted
        self.service.register_notice({
            "order_no": "BM-001", "detail": "交通通告", "status": "open",
            "external_ref": "NT-1", "valid_until": "2099-01-01T00:00:00Z",
            "request_no": "REQ-2",
        }, "officer", "bridge_engineer")
        self.service.register_verification({
            "order_no": "BM-001", "detail": "现场核查完成", "status": "closed",
            "external_ref": "VC-1", "request_no": "REQ-3",
        }, "officer", "bridge_engineer")
        rec = self.service.get_recommendation("BM-001", "viewer")
        self.assertEqual(rec["active"]["level"], "restricted")
        self.assertEqual(rec["active"]["status"], "active")

    def test_notice_expiry_invalidates_recommendation(self):
        self._alert()
        self.service.register_notice({
            "order_no": "BM-001", "detail": "交通通告", "status": "open",
            "external_ref": "NT-1", "valid_until": "2099-01-01T00:00:00Z",
            "request_no": "REQ-2",
        }, "officer", "bridge_engineer")
        self.service.register_verification({
            "order_no": "BM-001", "detail": "核查完成", "status": "closed",
            "external_ref": "VC-1", "request_no": "REQ-3",
        }, "officer", "bridge_engineer")
        self.assertEqual(self.service.get_recommendation("BM-001", "viewer")["active"]["level"],
                         "restricted")

        # 模拟时间流逝：通告失效
        with self.repo._lock, self.repo.conn:
            self.repo.conn.execute(
                "UPDATE records SET valid_until='2020-01-01T00:00:00Z' WHERE kind='notice'")
        result = self.service.check_expired_notices("system", "viewer")
        self.assertEqual(len(result["expired"]), 1)

        rec = self.service.get_recommendation("BM-001", "viewer")
        self.assertEqual(rec["active"]["level"], "advisory")
        self.assertEqual(rec["active"]["status"], "active")
        # 旧建议已失效
        invalid = [h for h in rec["history"] if h["status"] == "invalid"]
        self.assertGreaterEqual(len(invalid), 1)
        # 审计可查
        audit = self.service.audit("viewer")
        actions = [e["action"] for e in audit]
        self.assertIn("notice_expired", actions)
        self.assertIn("recommendation_invalidated", actions)
        self.assertIn("recommendation_computed", actions)

    def test_verification_reopen_invalidates_recommendation(self):
        self._alert()
        self.service.register_notice({
            "order_no": "BM-001", "detail": "通告", "status": "open",
            "external_ref": "NT-1", "valid_until": "2099-01-01T00:00:00Z",
            "request_no": "REQ-2",
        }, "officer", "bridge_engineer")
        self.service.register_verification({
            "order_no": "BM-001", "detail": "核查完成", "status": "closed",
            "external_ref": "VC-1", "request_no": "REQ-3",
        }, "officer", "bridge_engineer")
        self.assertEqual(self.service.get_recommendation("BM-001", "viewer")["active"]["level"],
                         "restricted")

        # 核查重开
        self.service.register_verification({
            "order_no": "BM-001", "detail": "核查重开", "status": "open",
            "external_ref": "VC-2", "request_no": "REQ-4",
        }, "officer", "bridge_engineer")
        rec = self.service.get_recommendation("BM-001", "viewer")
        self.assertEqual(rec["active"]["level"], "advisory")
        audit = self.service.audit("viewer")
        self.assertIn("recommendation_invalidated", [e["action"] for e in audit])

    def test_monitoring_change_invalidates_recommendation(self):
        self._alert(severity="warning", quantity=12, threshold=6)
        self.service.register_notice({
            "order_no": "BM-001", "detail": "通告", "status": "open",
            "external_ref": "NT-1", "valid_until": "2099-01-01T00:00:00Z",
            "request_no": "REQ-2",
        }, "officer", "bridge_engineer")
        self.service.register_verification({
            "order_no": "BM-001", "detail": "核查完成", "status": "closed",
            "external_ref": "VC-1", "request_no": "REQ-3",
        }, "officer", "bridge_engineer")
        self.assertEqual(self.service.get_recommendation("BM-001", "viewer")["active"]["level"],
                         "restricted")

        # 监测值变化 → 重算
        self.service.update_monitoring({
            "order_no": "BM-001", "quantity": 1, "threshold": 6, "severity": "normal",
            "expected_version": 1, "request_no": "REQ-5",
        }, "officer", "sensor_operator")
        rec = self.service.get_recommendation("BM-001", "viewer")
        self.assertEqual(rec["active"]["level"], "normal")
        audit = self.service.audit("viewer")
        self.assertIn("monitoring_updated", [e["action"] for e in audit])

    def test_offline_draft_merge_fast_forward(self):
        # 中心已有告警
        self._alert(order_no="BM-002", request_no="REQ-1")
        base = self.repo.snapshot_hash("BM-002")

        # 断网存草稿（核查记录）
        self.service.save_draft({
            "request_no": "DRAFT-1", "order_no": "BM-002", "kind": "verification",
            "payload": {"detail": "现场核查", "status": "closed", "external_ref": "VC-9"},
            "base_hash": base,
        }, "officer", "bridge_engineer")

        # 回网合并
        result = self.service.merge_drafts("officer", "bridge_engineer")
        self.assertEqual(len(result["outcomes"]), 1)
        self.assertEqual(result["outcomes"][0]["outcome"], "merged")

        # 原草稿保留
        drafts = self.service.list_drafts("viewer")
        self.assertEqual(len(drafts), 1)
        self.assertEqual(drafts[0]["status"], "merged")

        # 核查记录已并入
        records = self.repo.list_records(
            self.repo._item_by_order_tx(self.repo.conn, "BM-002")["id"])
        self.assertTrue(any(r["external_ref"] == "VC-9" for r in records))

    def test_both_sides_changed_pending_confirmation_center_notice_untouched(self):
        # 中心告警 + 中心通告
        self._alert(order_no="BM-003", request_no="REQ-1")
        self.service.register_notice({
            "order_no": "BM-003", "detail": "中心通告", "status": "open",
            "external_ref": "NT-1", "valid_until": "2099-01-01T00:00:00Z",
            "request_no": "REQ-2",
        }, "officer", "bridge_engineer")

        # 断网期间本地也改了同一通告（同 external_ref，不同内容）
        self.service.save_draft({
            "request_no": "DRAFT-2", "order_no": "BM-003", "kind": "notice",
            "payload": {"detail": "本地通告", "status": "open", "external_ref": "NT-1",
                        "valid_until": "2099-12-31T00:00:00Z"},
            "base_hash": None,
        }, "officer", "bridge_engineer")

        # 回网合并 → 两边都改过，待确认
        result = self.service.merge_drafts("officer", "bridge_engineer")
        self.assertEqual(result["outcomes"][0]["outcome"], "pending_confirmation")

        # 中心通告未被覆盖
        item = self.repo._item_by_order_tx(self.repo.conn, "BM-003")
        records = self.repo.list_records(item["id"])
        notice = next(r for r in records if r["external_ref"] == "NT-1")
        self.assertEqual(notice["detail"], "中心通告")

        # 草稿仍为待确认
        draft = self.service.list_drafts("viewer", "pending_confirmation")[0]
        self.assertEqual(draft["request_no"], "DRAFT-2")

        # 尝试用本地草稿覆盖中心通告 → 禁止
        with self.assertRaises(ConflictError):
            self.service.resolve_pending(
                {"draft_id": draft["id"], "keep": "local"}, "officer", "bridge_engineer")

        # 保留中心版本
        resolved = self.service.resolve_pending(
            {"draft_id": draft["id"], "keep": "center"}, "officer", "bridge_engineer")
        self.assertEqual(resolved["draft"]["status"], "merged")

    def test_idempotent_retry_by_request_no(self):
        # 首次写入
        first = self._alert(order_no="BM-004", request_no="REQ-1")
        # 同请求编号重试 → 幂等回放，不重复建告警
        second = self._alert(order_no="BM-004", request_no="REQ-1")
        self.assertEqual(first["item"]["id"], second["item"]["id"])

        # 失败后按原请求编号重试：先提交非法数据（无状态变更），再用同编号提交合法数据
        with self.assertRaises(Exception):
            self.service.register_alert({
                "order_no": "BM-005", "title": "", "description": "x",
                "severity": "warning", "quantity": 1, "threshold": 1,
                "request_no": "REQ-BAD",
            }, "officer", "sensor_operator")
        # 非法数据未入库
        self.assertIsNone(self.repo._item_by_order_tx(self.repo.conn, "BM-005"))
        # 同编号重试成功
        ok = self.service.register_alert({
            "order_no": "BM-005", "title": "重试成功", "description": "x",
            "severity": "warning", "quantity": 1, "threshold": 1,
            "request_no": "REQ-BAD",
        }, "officer", "sensor_operator")
        self.assertEqual(ok["item"]["external_ref"], "BM-005")

        # 审计可查且状态变更都有记录
        audit = self.service.audit("viewer")
        actions = [e["action"] for e in audit]
        self.assertEqual(actions.count("alert_registered"), 2)  # BM-004 与 BM-005 各一次
        self.assertTrue(self.repo.verify_audit_chain())

    def test_state_change_always_has_audit_record(self):
        self._alert(order_no="BM-006", request_no="REQ-1")
        self.service.register_notice({
            "order_no": "BM-006", "detail": "通告", "status": "open",
            "external_ref": "NT-1", "valid_until": "2099-01-01T00:00:00Z",
            "request_no": "REQ-2",
        }, "officer", "bridge_engineer")
        self.service.update_monitoring({
            "order_no": "BM-006", "quantity": 20, "threshold": 6, "severity": "critical",
            "expected_version": 1, "request_no": "REQ-3",
        }, "officer", "sensor_operator")
        # 每次状态变更都有对应审计
        audit = self.service.audit("viewer")
        by_action = {}
        for e in audit:
            by_action.setdefault(e["action"], []).append(e)
        self.assertIn("alert_registered", by_action)
        self.assertIn("record_registered", by_action)
        self.assertIn("monitoring_updated", by_action)
        self.assertIn("recommendation_computed", by_action)
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()

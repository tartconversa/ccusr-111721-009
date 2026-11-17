import json
import tempfile
import unittest
from pathlib import Path

from exchange import Exchange
from exchange.staging import StalePreviewError


class StagingFlowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Exchange(Path(self.temp.name) / "exchange.db")
        service = self.service
        service.catalog.register("flow", "机构甲", "甲地", "restricted", [("count", "通行计数", "integer", False)], "2026-11-01")
        service.catalog.register("local", "机构甲", "乙地", "public", [("note", "备注", "text", False)], "2026-11-01")
        service.catalog.ingest("item-1", "flow", {"count": 8}, "2026-11-02")
        service.catalog.ingest("item-2", "local", {"note": "x"}, "2026-11-02")
        service.grants.issue("g-1", "flow", "机构乙", "运行协调", "2026-12-31", "2026-11-03")
        service.grants.issue("g-2", "local", "机构乙", "运行协调", "2026-12-31", "2026-11-03")
        service.grants.issue("g-3", "flow", "机构丙", "运行协调", "2026-12-31", "2026-11-03")
        service.grants.issue("g-4", "local", "机构丙", "运行协调", "2026-12-31", "2026-11-03")
        service.policies.set("甲地", "restricted", "运行协调", "allow", "2026-11-03", "机构甲")
        service.policies.set("乙地", "public", "运行协调", "allow", "2026-11-03", "机构甲")
        self.revision = service.products.assemble("report", "通行观察", ["item-1", "item-2"], "2026-11-04", "机构甲")

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def propose_deny(self):
        self.service.staging.propose("rv-1", "甲地", "restricted", "运行协调", "deny", "2026-11-05", "机构甲")

    def test_pending_revision_keeps_current_deliveries(self):
        self.propose_deny()
        receipt = self.service.delivery.send("d-1", "report", self.revision, "机构乙", "运行协调", "2026-11-05")
        pinned = json.loads(receipt["policy_revisions"])
        self.assertEqual(pinned["flow"], {
            "jurisdiction": "甲地", "classification": "restricted", "purpose": "运行协调", "revision": 1,
        })

    def test_preview_explains_losers_with_lineage_and_grants(self):
        self.propose_deny()
        preview = self.service.staging.preview("rv-1", "pv-1", "2026-11-05", "机构甲")
        self.assertEqual({entry["recipient"] for entry in preview["impacts"]}, {"机构乙", "机构丙"})
        entry = next(item for item in preview["impacts"] if item["recipient"] == "机构乙")
        self.assertEqual(entry["change"], "lose")
        self.assertEqual((entry["product"], entry["product_revision"], entry["purpose"]), ("report", self.revision, "运行协调"))
        self.assertEqual(len(entry["inputs"]), 1)
        lineage = entry["inputs"][0]
        self.assertEqual(lineage["asset"], "item-1")
        self.assertEqual(lineage["source"], "flow")
        self.assertEqual(lineage["owner"], "机构甲")
        self.assertEqual(lineage["jurisdiction"], "甲地")
        self.assertEqual(lineage["classification"], "restricted")
        self.assertEqual(lineage["grant"], "g-1")
        self.assertEqual((lineage["decision_before"], lineage["decision_after"]), ("allow", "deny"))

    def test_publish_then_credentials_pin_effective_revision(self):
        self.propose_deny()
        self.service.staging.preview("rv-1", "pv-1", "2026-11-05", "机构甲")
        result = self.service.staging.publish("rv-1", "2026-11-06", "机构甲")
        self.assertEqual(result["published_revision"], 2)
        with self.assertRaises(PermissionError):
            self.service.delivery.send("d-2", "report", self.revision, "机构乙", "运行协调", "2026-11-06")
        self.service.staging.propose("rv-2", "甲地", "restricted", "运行协调", "allow", "2026-11-07", "机构甲")
        preview = self.service.staging.preview("rv-2", "pv-2", "2026-11-07", "机构甲")
        self.assertEqual({entry["change"] for entry in preview["impacts"]}, {"gain"})
        self.assertEqual(self.service.staging.publish("rv-2", "2026-11-08", "机构甲")["published_revision"], 3)
        receipt = self.service.delivery.send("d-3", "report", self.revision, "机构乙", "运行协调", "2026-11-08")
        pinned = json.loads(receipt["policy_revisions"])
        self.assertEqual(pinned["flow"]["revision"], 3)
        self.assertEqual((pinned["flow"]["jurisdiction"], pinned["flow"]["classification"]), ("甲地", "restricted"))

    def test_grant_revocation_marks_preview_stale_and_blocks_publish(self):
        self.propose_deny()
        self.service.staging.preview("rv-1", "pv-1", "2026-11-05", "机构甲")
        self.service.grants.revoke("g-1", "2026-11-06")
        status = self.service.staging.changes("pv-1", "2026-11-06")
        self.assertFalse(status["fresh"])
        permit_changes = [change for change in status["changes"] if change["kind"] == "permit"]
        self.assertEqual(len(permit_changes), 1)
        self.assertEqual(permit_changes[0]["change"], "revoked")
        self.assertIn("已撤销", permit_changes[0]["message"])
        with self.assertRaises(StalePreviewError) as caught:
            self.service.staging.publish("rv-1", "2026-11-06", "机构甲")
        self.assertIn("已撤销", str(caught.exception))
        refreshed = self.service.staging.preview("rv-1", "pv-2", "2026-11-07", "机构甲")
        self.assertEqual([entry["recipient"] for entry in refreshed["impacts"]], ["机构丙"])
        self.assertEqual(self.service.staging.publish("rv-1", "2026-11-08", "机构甲")["published_revision"], 2)
        self.assertEqual(self.service.policies.decision("甲地", "restricted", "运行协调"), ("deny", 2))

    def test_source_deactivation_reported_in_changes(self):
        self.propose_deny()
        self.service.staging.preview("rv-1", "pv-1", "2026-11-05", "机构甲")
        self.service.catalog.deactivate("flow", "2026-11-06")
        status = self.service.staging.changes("pv-1", "2026-11-06")
        self.assertFalse(status["fresh"])
        source_changes = [change for change in status["changes"] if change["kind"] == "source"]
        self.assertEqual(source_changes[0]["change"], "deactivated")
        self.assertIn("已停用", source_changes[0]["message"])
        with self.assertRaises(StalePreviewError):
            self.service.staging.publish("rv-1", "2026-11-06", "机构甲")

    def test_publish_requires_pending_state_and_preview(self):
        self.propose_deny()
        with self.assertRaises(ValueError):
            self.service.staging.publish("rv-1", "2026-11-06", "机构甲")
        self.service.staging.preview("rv-1", "pv-1", "2026-11-05", "机构甲")
        self.service.staging.publish("rv-1", "2026-11-06", "机构甲")
        with self.assertRaises(ValueError):
            self.service.staging.publish("rv-1", "2026-11-07", "机构甲")
        with self.assertRaises(ValueError):
            self.service.staging.preview("rv-1", "pv-2", "2026-11-07", "机构甲")

    def test_new_proposal_supersedes_pending_revision(self):
        self.propose_deny()
        self.service.staging.propose("rv-2", "甲地", "restricted", "运行协调", "allow", "2026-11-06", "机构甲")
        self.assertEqual(self.service.staging.get("rv-1")["state"], "superseded")
        with self.assertRaises(ValueError):
            self.service.staging.publish("rv-1", "2026-11-06", "机构甲")
        self.service.staging.preview("rv-2", "pv-2", "2026-11-06", "机构甲")
        self.assertEqual(self.service.staging.publish("rv-2", "2026-11-07", "机构甲")["published_revision"], 2)

    def test_invalid_decision_and_unknown_revision_rejected(self):
        with self.assertRaises(ValueError):
            self.service.staging.propose("rv-9", "甲地", "restricted", "运行协调", "maybe", "2026-11-05", "机构甲")
        with self.assertRaises(KeyError):
            self.service.staging.get("rv-9")
        with self.assertRaises(KeyError):
            self.service.staging.preview("rv-9", "pv-9", "2026-11-05", "机构甲")

    def test_deactivate_and_revoke_validate_state(self):
        self.service.catalog.deactivate("flow", "2026-11-06")
        with self.assertRaises(ValueError):
            self.service.catalog.deactivate("flow", "2026-11-07")
        self.service.grants.revoke("g-1", "2026-11-06")
        with self.assertRaises(ValueError):
            self.service.grants.revoke("g-1", "2026-11-07")
        with self.assertRaises(KeyError):
            self.service.grants.revoke("g-9", "2026-11-07")


if __name__ == "__main__":
    unittest.main()

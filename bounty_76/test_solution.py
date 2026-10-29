#!/usr/bin/env python3
import os
import tempfile
import unittest
from solution import FinMindGDPREngine


class TestFinMindGDPRWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "finmind_gdpr.sqlite")
        self.engine = FinMindGDPREngine(self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_01_deterministic_export_and_zero_residual_erasure(self):
        self.engine.seed_user_record(
            "usr-1121",
            "theabsolutesectorz@gmail.com",
            "Michael Joseph Sandford",
            "TAX-1121-ROOT",
            [
                {"tx_id": "tx-001", "amount_cents": 50000, "category": "Bounty", "memo_pii": "Algora FinMind #76"},
                {"tx_id": "tx-002", "amount_cents": 35000, "category": "Bounty", "memo_pii": "Golem Worker"},
            ],
        )
        res = self.engine.export_and_erase_user("usr-1121", "op-gdpr-1121-01")
        self.assertFalse(res["idempotent_replay"])
        self.assertEqual(res["residual_rows"], 0)
        self.assertEqual(len(res["export_bundle"]["transactions"]), 2)
        self.assertEqual(res["pre_state_sha256"], res["export_payload_sha256"])

        # Idempotent replay must return identical receipt without error
        replay = self.engine.export_and_erase_user("usr-1121", "op-gdpr-1121-01")
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["hmac_signature"], res["hmac_signature"])
        self.assertEqual(replay["post_state_sha256"], res["post_state_sha256"])


if __name__ == "__main__":
    unittest.main()

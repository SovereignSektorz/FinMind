#!/usr/bin/env python3
"""
FinMind Issue #76 — Deterministic SQLite WAL PII Export, Cryptographic Erasure
& GDPR Article 15/17 Audit Receipt Engine.
Author: Michael Joseph Sandford (1121 ROOT / SOV-MS-001)
"""

import hashlib
import hmac
import json
import sqlite3
import time
from typing import Dict, Any, List


class FinMindGDPREngine:
    """Idempotent SQLite WAL PII export and cryptographic erasure workflow."""

    def __init__(self, db_path: str, signing_key: bytes = b"1121110710060318"):
        self.db_path = db_path
        self.signing_key = signing_key
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=FULL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA secure_delete=ON;")
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    tax_identifier TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS financial_transactions (
                    tx_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    amount_cents INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    memo_pii TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS gdpr_audit_ledger (
                    op_key TEXT PRIMARY KEY,
                    user_id_hash TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    pre_state_sha256 TEXT NOT NULL,
                    export_payload_sha256 TEXT NOT NULL,
                    post_state_sha256 TEXT NOT NULL,
                    residual_rows INTEGER NOT NULL,
                    hmac_signature TEXT NOT NULL,
                    executed_at INTEGER NOT NULL
                );
            """)
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def seed_user_record(self, user_id: str, email: str, full_name: str, tax_id: str, txs: List[Dict[str, Any]]) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                "INSERT OR REPLACE INTO users (user_id, email, full_name, tax_identifier, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, email, full_name, tax_id, 1793212800),
            )
            for tx in txs:
                conn.execute(
                    "INSERT OR REPLACE INTO financial_transactions (tx_id, user_id, amount_cents, category, memo_pii, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (tx["tx_id"], user_id, tx["amount_cents"], tx["category"], tx["memo_pii"], 1793212800),
                )
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def export_and_erase_user(self, user_id: str, op_key: str) -> Dict[str, Any]:
        """Atomically exports user PII (Art. 15) and executes zero-residual erasure (Art. 17)."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            existing = conn.execute(
                "SELECT * FROM gdpr_audit_ledger WHERE op_key = ?", (op_key,)
            ).fetchone()
            if existing:
                conn.execute("COMMIT;")
                return {
                    "idempotent_replay": True,
                    "op_key": existing["op_key"],
                    "user_id_hash": existing["user_id_hash"],
                    "pre_state_sha256": existing["pre_state_sha256"],
                    "export_payload_sha256": existing["export_payload_sha256"],
                    "post_state_sha256": existing["post_state_sha256"],
                    "residual_rows": existing["residual_rows"],
                    "hmac_signature": existing["hmac_signature"],
                }

            user_row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
            tx_rows = conn.execute(
                "SELECT * FROM financial_transactions WHERE user_id = ? ORDER BY tx_id ASC", (user_id,)
            ).fetchall()

            export_bundle = {
                "gdpr_article": "Article 15 Right of Access & Article 20 Data Portability",
                "user": dict(user_row) if user_row else None,
                "transactions": [dict(r) for r in tx_rows],
            }
            export_bytes = json.dumps(export_bundle, sort_keys=True).encode("utf-8")
            export_sha256 = hashlib.sha256(export_bytes).hexdigest()
            pre_state_sha256 = export_sha256

            # Execute Article 17 Right to Erasure
            conn.execute("DELETE FROM financial_transactions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

            # Verify zero residual rows across all PII tables
            rem_u = conn.execute("SELECT COUNT(*) AS c FROM users WHERE user_id = ?", (user_id,)).fetchone()["c"]
            rem_t = conn.execute("SELECT COUNT(*) AS c FROM financial_transactions WHERE user_id = ?", (user_id,)).fetchone()["c"]
            residual_rows = int(rem_u + rem_t)
            if residual_rows != 0:
                raise RuntimeError(f"GDPR Erasure invariant breach: {residual_rows} residual rows remain.")

            user_id_hash = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
            post_state_payload = json.dumps(
                {"user_id_hash": user_id_hash, "residual_rows": residual_rows, "erased": True},
                sort_keys=True,
            ).encode("utf-8")
            post_state_sha256 = hashlib.sha256(post_state_payload).hexdigest()

            sig_msg = f"{op_key}:{user_id_hash}:{pre_state_sha256}:{post_state_sha256}:{residual_rows}".encode("utf-8")
            hmac_sig = hmac.new(self.signing_key, sig_msg, hashlib.sha256).hexdigest()

            conn.execute(
                """INSERT INTO gdpr_audit_ledger
                   (op_key, user_id_hash, action_type, pre_state_sha256, export_payload_sha256,
                    post_state_sha256, residual_rows, hmac_signature, executed_at)
                   VALUES (?, ?, 'EXPORT_AND_ERASE', ?, ?, ?, ?, ?, ?)""",
                (op_key, user_id_hash, pre_state_sha256, export_sha256, post_state_sha256, residual_rows, hmac_sig, 1793212800),
            )
            conn.execute("COMMIT;")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")

            return {
                "idempotent_replay": False,
                "op_key": op_key,
                "user_id_hash": user_id_hash,
                "export_bundle": export_bundle,
                "pre_state_sha256": pre_state_sha256,
                "export_payload_sha256": export_sha256,
                "post_state_sha256": post_state_sha256,
                "residual_rows": residual_rows,
                "hmac_signature": hmac_sig,
            }
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

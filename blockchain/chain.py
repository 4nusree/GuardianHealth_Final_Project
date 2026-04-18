import os
import json
import base64
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from .block import Block


class HealthcareBlockchain:
    DIFFICULTY    = 3
    ANCHOR_FILE   = "blockchain/anchor.txt"
    KEY_FILE      = "blockchain/signing_key.pem"

    def __init__(self, database_url: str):
        self.database_url  = database_url
        self._private_key  = self._load_or_generate_key()
        self._public_key   = self._private_key.public_key()
        self.chain: list[Block] = []
        self._load_chain()
        if not self.chain:
            self._create_genesis()

    # ── Key Management ────────────────────────────────────────────────────────

    def _load_or_generate_key(self):
        os.makedirs("blockchain", exist_ok=True)
        if os.path.exists(self.KEY_FILE):
            with open(self.KEY_FILE, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        key = ec.generate_private_key(ec.SECP256K1())
        with open(self.KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        print("[Blockchain] New ECDSA signing key generated → blockchain/signing_key.pem")
        return key

    def get_public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    # ── Proof-of-Work ─────────────────────────────────────────────────────────

    def _mine_block(self, block: Block) -> None:
        target = "0" * self.DIFFICULTY
        block.difficulty_used = self.DIFFICULTY
        while not block.hash.startswith(target):
            block.nonce += 1
            block.hash = block.compute_hash()

    # ── Signing ───────────────────────────────────────────────────────────────

    def _sign_block(self, block_hash: str) -> str:
        sig = self._private_key.sign(block_hash.encode(), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(sig).decode()

    def _verify_signature(self, block_hash: str, signature: str) -> bool:
        try:
            self._public_key.verify(
                base64.b64decode(signature),
                block_hash.encode(),
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except (InvalidSignature, Exception):
            return False

    # ── Anchor (Improvement #1) ───────────────────────────────────────────────

    def _update_anchor(self, latest_hash: str) -> None:
        os.makedirs("blockchain", exist_ok=True)
        with open(self.ANCHOR_FILE, "w") as f:
            f.write(latest_hash)

    def _verify_anchor(self) -> bool:
        if not self.chain:
            return True
        if not os.path.exists(self.ANCHOR_FILE):
            return False
        with open(self.ANCHOR_FILE) as f:
            stored = f.read().strip()
        return stored == self.chain[-1].hash

    # ── DB Persistence ────────────────────────────────────────────────────────

    def _get_conn(self):
        return psycopg2.connect(self.database_url)

    def _load_chain(self) -> None:
        conn = self._get_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM blockchain ORDER BY block_index ASC")
                rows = cur.fetchall()
            self.chain = [
                Block.from_dict({
                    "index":          row["block_index"],
                    "timestamp":      row["timestamp"],
                    "data":           row["data"],
                    "previous_hash":  row["previous_hash"],
                    "nonce":          row["nonce"],
                    "difficulty_used": row["difficulty_used"],
                    "hash":           row["hash"],
                    "signature":      row.get("signature"),
                })
                for row in rows
            ]
        except Exception:
            self.chain = []
        finally:
            conn.close()

    def _persist_block(self, block: Block) -> None:
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO blockchain"
                    "(block_index, timestamp, data, previous_hash, nonce, difficulty_used, hash, signature)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        block.index,
                        block.timestamp,
                        json.dumps(block.data),
                        block.previous_hash,
                        block.nonce,
                        block.difficulty_used,
                        block.hash,
                        block.signature,
                    ),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Genesis ───────────────────────────────────────────────────────────────

    def _create_genesis(self) -> None:
        genesis = Block(
            index=0,
            data={
                "event":   "GuardianHealth Blockchain Initialized",
                "system":  "Healthcare IAM — Zero Trust Security Framework",
                "version": "1.0",
            },
            previous_hash="0" * 64,
        )
        self._mine_block(genesis)
        genesis.signature = self._sign_block(genesis.hash)
        self._persist_block(genesis)
        self.chain.append(genesis)
        self._update_anchor(genesis.hash)
        print(f"[Blockchain] Genesis block mined → {genesis.hash[:16]}…")

    # ── Public API ────────────────────────────────────────────────────────────

    def add_block(self, data: dict) -> Block:
        last     = self.chain[-1]
        new_ts   = datetime.now(timezone.utc).isoformat()

        # Improvement #3 — Timestamp monotonicity enforcement
        if new_ts <= last.timestamp:
            import time
            time.sleep(0.001)
            new_ts = datetime.now(timezone.utc).isoformat()

        block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=last.hash,
            timestamp=new_ts,
        )

        # Improvement #3 — Proof-of-Work with locked difficulty
        self._mine_block(block)

        # Improvement #2 — ECDSA signature
        block.signature = self._sign_block(block.hash)

        # Improvement #5 — Append-only (no update paths exist in this class)
        self._persist_block(block)
        self.chain.append(block)

        # Improvement #1 — Update external anchor
        self._update_anchor(block.hash)

        return block

    def is_chain_valid(self) -> tuple[bool, list[dict]]:
        issues: list[dict] = []
        target  = "0" * self.DIFFICULTY

        # Improvement #1 — Verify anchor
        if not self._verify_anchor():
            issues.append({
                "block":   "anchor",
                "problem": "Anchor mismatch — chain tip may have been silently replaced",
            })

        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

            # Check #1 — Hash integrity (data not modified)
            if current.hash != current.compute_hash():
                issues.append({
                    "block":   i,
                    "problem": "Hash mismatch — block data was modified",
                })

            # Check #2 — Chain linkage (not de-chained)
            if current.previous_hash != previous.hash:
                issues.append({
                    "block":   i,
                    "problem": "Chain broken — previous_hash does not match predecessor",
                })

            # Check #3 — Timestamp monotonicity (not backdated)
            if current.timestamp <= previous.timestamp:
                issues.append({
                    "block":   i,
                    "problem": "Timestamp violation — block is not strictly after its predecessor",
                })

            # Check #4 — Difficulty consistency (re-mining shortcut prevention)
            expected_target = "0" * current.difficulty_used
            if not current.hash.startswith(expected_target):
                issues.append({
                    "block":   i,
                    "problem": f"Proof-of-work invalid — block re-mined with wrong difficulty ({current.difficulty_used})",
                })

            # Check #2 — Signature verification (prevents silent re-computation)
            if current.signature:
                if not self._verify_signature(current.hash, current.signature):
                    issues.append({
                        "block":   i,
                        "problem": "Signature invalid — block was re-mined without the server signing key",
                    })
            else:
                issues.append({
                    "block":   i,
                    "problem": "Missing signature — block has no cryptographic proof of origin",
                })

        return len(issues) == 0, issues

    def get_chain_summary(self) -> dict:
        valid, issues = self.is_chain_valid()
        return {
            "total_blocks":  len(self.chain),
            "valid":         valid,
            "issues":        issues,
            "latest_hash":   self.chain[-1].hash if self.chain else None,
            "anchor_intact": self._verify_anchor(),
        }

    def get_chain_dict(self) -> list[dict]:
        return [b.to_dict() for b in self.chain]

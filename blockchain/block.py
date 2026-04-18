import hashlib
import json
from datetime import datetime, timezone


class Block:
    def __init__(
        self,
        index,
        data,
        previous_hash,
        timestamp=None,
        nonce=0,
        difficulty_used=3,
        hash=None,
        signature=None,
    ):
        self.index = index
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.difficulty_used = difficulty_used
        self.hash = hash or self.compute_hash()
        self.signature = signature

    def compute_hash(self) -> str:
        block_str = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "data": self.data,
                "previous_hash": self.previous_hash,
                "nonce": self.nonce,
                "difficulty_used": self.difficulty_used,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_str.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "difficulty_used": self.difficulty_used,
            "hash": self.hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(
            index=d["index"],
            data=d["data"],
            previous_hash=d["previous_hash"],
            timestamp=d["timestamp"],
            nonce=d["nonce"],
            difficulty_used=d.get("difficulty_used", 3),
            hash=d["hash"],
            signature=d.get("signature"),
        )

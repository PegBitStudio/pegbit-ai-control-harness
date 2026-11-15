from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENESIS_HASH = "0" * 64


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    timestamp: str
    event_type: str
    actor: str
    payload: dict[str, Any]
    prev_hash: str
    record_hash: str


class AuditChain:
    """Tamper-evident SHA-256 hash-chained JSONL execution log for AI Control."""

    def __init__(self, log_path: str | Path) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        if self.log_path.exists():
            lines = [ln for ln in self.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                last = json.loads(lines[-1])
                self._seq = int(last["seq"]) + 1
                self._prev_hash = str(last["record_hash"])

    @staticmethod
    def compute_hash(seq: int, timestamp: str, event_type: str, actor: str, payload: dict[str, Any], prev_hash: str) -> str:
        body = {
            "seq": seq,
            "timestamp": timestamp,
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        return hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()

    def append(self, event_type: str, actor: str, payload: dict[str, Any]) -> AuditRecord:
        timestamp = datetime.now(timezone.utc).isoformat()
        record_hash = self.compute_hash(self._seq, timestamp, event_type, actor, payload, self._prev_hash)
        record = AuditRecord(
            seq=self._seq,
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            payload=payload,
            prev_hash=self._prev_hash,
            record_hash=record_hash,
        )
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical_json(asdict(record)) + "\n")
        self._seq += 1
        self._prev_hash = record_hash
        return record


def verify_audit_log(log_path: str | Path) -> tuple[bool, int, str | None]:
    """Verify an audit JSONL chain offline. Returns (valid, record_count, error_message)."""
    path = Path(log_path)
    if not path.exists():
        return False, 0, "Audit log does not exist"

    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    expected_prev = GENESIS_HASH
    for idx, line in enumerate(lines):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            return False, idx, f"Malformed JSON at line {idx + 1}: {exc}"

        if int(row.get("seq", -1)) != idx:
            return False, idx, f"Sequence mismatch at line {idx + 1}: expected {idx}, got {row.get('seq')}"
        if row.get("prev_hash") != expected_prev:
            return False, idx, f"prev_hash mismatch at seq {idx}"

        expected_hash = AuditChain.compute_hash(
            seq=row["seq"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            actor=row["actor"],
            payload=row["payload"],
            prev_hash=row["prev_hash"],
        )
        if row.get("record_hash") != expected_hash:
            return False, idx, f"record_hash mismatch at seq {idx} (tampered payload)"
        expected_prev = expected_hash

    return True, len(lines), None

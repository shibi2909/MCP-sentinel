"""M9 - Tamper-Evident Audit Logging.

Each record stores the SHA-256 hash of the previous record, and its own hash covers all of its
fields *including* that previous hash:

    record_hash_n = SHA256( canonical_json(seq, timestamp, request_id, event_type, actor,
                                           action, risk_score, details, prev_hash = record_hash_{n-1}) )

Changing, deleting or reordering any record breaks the chain from that point on, which
`verify_chain` detects. (Limitation: an attacker who can rewrite the WHOLE database could
recompute every hash; anchoring the latest hash externally - e.g. Hyperledger Fabric - is listed
as future work.)
"""
import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import DATA_DIR
from app.models import AuditLog

GENESIS_HASH = "0" * 64
_append_lock = threading.Lock()  # sequence numbers and prev_hash must be assigned atomically

# Keeps the original values of records modified by the tampering demo so the demo can be undone.
# Stored in a file so that it survives a backend restart.
_TAMPER_BACKUP_FILE = DATA_DIR / "audit_tamper_demo_backup.json"


def _load_backup() -> dict[int, dict]:
    if not _TAMPER_BACKUP_FILE.exists():
        return {}
    return {int(k): v for k, v in json.loads(_TAMPER_BACKUP_FILE.read_text(encoding="utf-8")).items()}


def _save_backup(backup: dict[int, dict]) -> None:
    _TAMPER_BACKUP_FILE.write_text(json.dumps({str(k): v for k, v in backup.items()}), encoding="utf-8")


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_record_hash(*, seq: int, timestamp: str, request_id: str | None, event_type: str, actor: str,
                        action: str, risk_score: float | None, details: dict, prev_hash: str) -> str:
    payload = {
        "seq": seq, "timestamp": timestamp, "request_id": request_id, "event_type": event_type,
        "actor": actor, "action": action,
        "risk_score": None if risk_score is None else round(float(risk_score), 2),
        "details": details, "prev_hash": prev_hash,
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def append_audit(db: Session, *, event_type: str, actor: str, action: str, risk_score: float | None = None,
                 request_id: str | None = None, details: dict | None = None) -> AuditLog:
    details = json.loads(_canonical(details or {}))  # normalise to plain JSON so hashing is stable
    with _append_lock:
        last = db.scalar(select(AuditLog).order_by(AuditLog.seq.desc()).limit(1))
        seq = 1 if last is None else last.seq + 1
        prev_hash = GENESIS_HASH if last is None else last.record_hash
        timestamp = datetime.now(timezone.utc).isoformat()
        score = None if risk_score is None else round(float(risk_score), 2)
        record = AuditLog(
            seq=seq, timestamp=timestamp, request_id=request_id, event_type=event_type, actor=actor,
            action=action, risk_score=score, details=details, prev_hash=prev_hash,
            record_hash=compute_record_hash(seq=seq, timestamp=timestamp, request_id=request_id,
                                            event_type=event_type, actor=actor, action=action,
                                            risk_score=score, details=details, prev_hash=prev_hash),
        )
        db.add(record)
        db.commit()
    return record


def verify_chain(db: Session) -> dict[str, Any]:
    """Recompute every hash and check every link. Returns a detailed verification report."""
    problems: list[dict] = []
    expected_prev = GENESIS_HASH
    expected_seq = 1
    total = 0
    for record in db.scalars(select(AuditLog).order_by(AuditLog.seq)):
        total += 1
        if record.seq != expected_seq:
            problems.append({"seq": record.seq, "problem": f"sequence gap: expected {expected_seq} (record deleted?)"})
        if record.prev_hash != expected_prev:
            problems.append({"seq": record.seq, "problem": "prev_hash does not match the previous record's hash (chain broken)"})
        recomputed = compute_record_hash(
            seq=record.seq, timestamp=record.timestamp, request_id=record.request_id,
            event_type=record.event_type, actor=record.actor, action=record.action,
            risk_score=record.risk_score, details=record.details, prev_hash=record.prev_hash,
        )
        if recomputed != record.record_hash:
            problems.append({"seq": record.seq, "problem": "record content was modified (hash mismatch)",
                             "stored_hash": record.record_hash, "recomputed_hash": recomputed})
        expected_prev = record.record_hash
        expected_seq = record.seq + 1
    return {
        "valid": not problems,
        "total_records": total,
        "first_invalid_seq": problems[0]["seq"] if problems else None,
        "problems": problems[:20],
        "latest_hash": expected_prev if total else None,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


def tamper_record_for_demo(db: Session, seq: int | None = None) -> dict[str, Any]:
    """Simulate an insider editing the database directly (bypassing the application).

    Picks the most recent BLOCK record (or the given seq) and rewrites it to look harmless.
    Only the action/risk fields change; hashes are NOT recomputed - exactly like a real attacker
    who edits rows without knowing (or being able to rewrite) the rest of the chain.
    """
    if seq is None:
        record = db.scalar(select(AuditLog).where(AuditLog.action == "BLOCK").order_by(AuditLog.seq.desc()).limit(1))
        if record is None:
            record = db.scalar(select(AuditLog).order_by(AuditLog.seq.desc()).limit(1))
    else:
        record = db.get(AuditLog, seq)
    if record is None:
        raise ValueError("no audit records exist yet")
    backup = _load_backup()
    if record.seq not in backup:
        backup[record.seq] = {"action": record.action, "risk_score": record.risk_score}
        _save_backup(backup)
    original = backup[record.seq]
    db.execute(update(AuditLog).where(AuditLog.seq == record.seq).values(action="ALLOW", risk_score=3.0))
    db.commit()
    return {"seq": record.seq, "original": original, "tampered": {"action": "ALLOW", "risk_score": 3.0}}


def restore_tampered_records(db: Session) -> list[int]:
    """Undo the demo tampering by writing back the original values (hashes then verify again)."""
    restored = []
    for seq, original in _load_backup().items():
        db.execute(update(AuditLog).where(AuditLog.seq == seq).values(**original))
        restored.append(seq)
    db.commit()
    _save_backup({})
    return restored


def tampered_seqs() -> list[int]:
    return sorted(_load_backup())


def clear_tamper_backup() -> None:
    _save_backup({})


def audit_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(AuditLog)) or 0

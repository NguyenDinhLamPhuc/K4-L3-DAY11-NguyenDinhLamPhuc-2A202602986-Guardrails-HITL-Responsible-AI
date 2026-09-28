"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[tuple[str, str | None], dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store the input and start time for a user's request."""
        self._open[(user_id, request_id)] = {
            "user_id": user_id,
            "request_id": request_id,
            "input": text,
            "timestamp": utc_now_iso(),
            "started_at": time.perf_counter(),
        }

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Complete a request with its output, decision, and latency in milliseconds."""
        finished_at = time.perf_counter()
        entry = self._open.pop((user_id, request_id), None)
        if entry is None:
            entry = {
                "user_id": user_id,
                "request_id": request_id,
                "input": None,
                "timestamp": utc_now_iso(),
            }
        started_at = entry.pop("started_at", None)
        entry.update(
            output=text,
            blocked=blocked,
            layer=layer,
            latency_ms=(finished_at - started_at) * 1000
            if started_at is not None else None,
        )
        self.logs.append(entry)

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(self.logs, handle, ensure_ascii=False, indent=2)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

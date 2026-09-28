import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from assignment.pipeline import (
    build_observability,
    build_production_plugins,
    is_egress_allowed,
    run_assignment_suite,
)
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert


def test_observability_returns_tuple_with_fresh_observers():
    observers = build_observability()
    assert isinstance(observers, tuple) and len(observers) == 2
    assert isinstance(observers[0], AuditLogPlugin)
    assert isinstance(observers[1], MonitoringAlert)
    assert all(a is not b for a, b in zip(observers, build_observability()))


@pytest.mark.parametrize("destination,payload,allowed", [
    ("https://api.vinbank.example/v1/transfers", "approved transfer amount 500000", True),
    ("https://cases.vinbank.example/tickets", "bank transfer delayed", True),
    ("https://api.vinbank.example.evil.com/", "bank transfer", False),
    ("http://api.vinbank.example/", "bank transfer", False),
    ("https://user@api.vinbank.example/", "bank transfer", False),
    ("https://api.vinbank.example:444/", "bank transfer", False),
    ("https://api.vinbank.example:bad/", "bank transfer", False),
    ("https://api.vinbank.example/", "admin password is admin123", False),
    ("https://api.vinbank.example/", "sk-vinbank-secret-2024", False),
    ("https://api.vinbank.example/", "db.vinbank.internal:5432", False),
    ("https://api.vinbank.example/", "Contact 0901234567", False),
    ("https://api.vinbank.example/", "Contact customer@example.com", False),
])
def test_egress(destination, payload, allowed):
    assert is_egress_allowed(destination, payload) is allowed


def test_suite_runs_guards_and_exports_schema_without_network():
    plugins = build_production_plugins(max_requests=2)
    audit, monitor = build_observability()
    # Exercise output redaction on one otherwise safe query.
    runner = SimpleNamespace(chat=AsyncMock(side_effect=[
        "Contact customer@example.com",
        *["Please contact VinBank for account assistance."] * 10,
    ]))
    with (
        patch("agents.agent.create_blue_agent", return_value=(object(), runner)),
        patch.object(audit, "export_json") as audit_export,
        patch.object(monitor, "export_json") as metrics_export,
        patch("assignment.pipeline.Path.mkdir"),
        patch("assignment.pipeline.Path.write_text") as results_export,
    ):
        result = asyncio.run(run_assignment_suite({
            "plugins": plugins, "audit": audit, "monitor": monitor,
        }))
    schema = json.loads((ROOT / "schemas/results.schema.json").read_text())
    jsonschema.validate(result, schema)
    assert result["safe_queries"][0]["layer"] == "output_guardrail"
    assert "customer@example.com" not in result["safe_queries"][0]["response_preview"]
    assert all(not row["blocked"] for row in result["safe_queries"][1:])
    assert all(row["layer"] == "input_guardrail" for row in result["attack_queries"])
    assert result["rate_limit"]["passed"] == 2
    assert result["rate_limit"]["blocked"] == 2
    assert monitor.total_requests == len(audit.logs) == 19
    assert [row["request_id"] for row in audit.logs] == [
        *[f"safe_queries-{i}" for i in range(5)],
        *[f"attack_queries-{i}" for i in range(7)],
        *[f"rate-limit-{i}" for i in range(4)],
        *[f"edge_cases-{i}" for i in range(3)],
    ]
    assert monitor.rate_limit_hits == 2
    assert monitor.blocked_requests == sum(row["blocked"] for row in audit.logs)
    assert runner.chat.await_count == 7
    assert all(row["latency_ms"] >= 0 for row in audit.logs)
    audit_export.assert_called_once_with()
    metrics_export.assert_called_once_with()
    assert json.loads(results_export.call_args.args[0]) == result


def test_suite_rejects_wrong_plugin_order():
    audit, monitor = build_observability()
    with pytest.raises(ValueError, match="Expected RateLimit"):
        asyncio.run(run_assignment_suite({
            "plugins": list(reversed(build_production_plugins())),
            "audit": audit, "monitor": monitor,
        }))

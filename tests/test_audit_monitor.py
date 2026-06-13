from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from github_credential_broker.audit_monitor import (
    MonitorConfig,
    parse_broker_audit_line,
    run_monitor_once,
)


def _config(tmp_path, **kwargs) -> MonitorConfig:
    values = {
        "archive_dir": tmp_path / "archive",
        "state_file": tmp_path / "state" / "monitor.json",
        "health_url": None,
        "denial_threshold": 5,
    }
    values.update(kwargs)
    return MonitorConfig(**values)


def _audit_line(payload: dict) -> str:
    return "2026-06-12T10:00:00Z host app[1]: broker_audit " + json.dumps(
        payload,
        sort_keys=True,
    )


def test_parse_broker_audit_line_ignores_non_audit_and_invalid_lines():
    assert parse_broker_audit_line("Authorization: Bearer secret-token") is None
    assert parse_broker_audit_line("broker_audit not-json") is None
    assert parse_broker_audit_line('broker_audit {"not_event":"x"}') is None

    parsed = parse_broker_audit_line(
        _audit_line({"event": "authorization_denied", "failure_class": "policy_miss"})
    )

    assert parsed == {"event": "authorization_denied", "failure_class": "policy_miss"}


def test_monitor_archives_only_normalized_broker_audit_payloads(tmp_path):
    now = datetime(2026, 6, 12, 10, 0, tzinfo=UTC)
    config = _config(tmp_path)

    result = run_monitor_once(
        config,
        now=now,
        journal_lines=[
            "noise line Authorization: Bearer secret-token",
            _audit_line(
                {
                    "event": "authorization_denied",
                    "failure_class": "policy_miss",
                    "requested_capabilities": ["deploy"],
                    "audit": {"repository": "cesaregarza/SplatTopConfig"},
                }
            ),
            "broker_audit not-json",
        ],
    )

    assert result.archived_events == 1
    archive = tmp_path / "archive" / "broker-audit-2026-06-12.jsonl"
    archive_text = archive.read_text(encoding="utf-8")
    assert "Authorization" not in archive_text
    assert "secret-token" not in archive_text
    archived = [json.loads(line) for line in archive_text.splitlines()]
    assert archived == [
        {
            "archived_at": "2026-06-12T10:00:00Z",
            "audit": {"repository": "cesaregarza/SplatTopConfig"},
            "event": "authorization_denied",
            "failure_class": "policy_miss",
            "requested_capabilities": ["deploy"],
        }
    ]


def test_denial_burst_sends_discord_alert(tmp_path):
    now = datetime(2026, 6, 12, 10, 0, tzinfo=UTC)
    config = _config(tmp_path, denial_threshold=2)
    sent: list[str] = []

    result = run_monitor_once(
        config,
        now=now,
        journal_lines=[
            _audit_line({"event": "authorization_denied", "failure_class": "policy_miss"}),
            _audit_line({"event": "rate_limited", "failure_class": "ip_rate_limited"}),
            _audit_line({"event": "credential_issued"}),
        ],
        alert_sender=sent.append,
    )

    assert result.denial_events == 2
    assert [alert.kind for alert in result.alerts] == ["denial_burst"]
    assert len(sent) == 1
    assert "denial burst detected" in sent[0]
    assert "authorization_denied=1" in sent[0]
    assert "rate_limited=1" in sent[0]
    assert "policy_miss=1" in sent[0]
    assert "ip_rate_limited=1" in sent[0]


def test_denial_burst_without_webhook_fails_closed(tmp_path):
    config = _config(tmp_path, denial_threshold=1)

    with pytest.raises(RuntimeError, match="no Discord webhook URL"):
        run_monitor_once(
            config,
            now=datetime(2026, 6, 12, 10, 0, tzinfo=UTC),
            journal_lines=[_audit_line({"event": "authentication_denied"})],
        )


def test_health_failure_alerts_after_sustained_failures_and_resets(tmp_path):
    config = _config(
        tmp_path,
        health_url="https://credentials.garz.ai/healthz",
        health_failure_threshold=2,
    )
    sent: list[str] = []
    now = datetime(2026, 6, 12, 10, 0, tzinfo=UTC)

    first = run_monitor_once(
        config,
        now=now,
        journal_lines=[],
        health_checker=lambda _url: False,
        alert_sender=sent.append,
    )
    second = run_monitor_once(
        config,
        now=now + timedelta(minutes=5),
        journal_lines=[],
        health_checker=lambda _url: False,
        alert_sender=sent.append,
    )
    third = run_monitor_once(
        config,
        now=now + timedelta(minutes=10),
        journal_lines=[],
        health_checker=lambda _url: False,
        alert_sender=sent.append,
    )
    recovered = run_monitor_once(
        config,
        now=now + timedelta(minutes=15),
        journal_lines=[],
        health_checker=lambda _url: True,
        alert_sender=sent.append,
    )
    after_reset = run_monitor_once(
        config,
        now=now + timedelta(minutes=20),
        journal_lines=[],
        health_checker=lambda _url: False,
        alert_sender=sent.append,
    )
    alerted_again = run_monitor_once(
        config,
        now=now + timedelta(minutes=25),
        journal_lines=[],
        health_checker=lambda _url: False,
        alert_sender=sent.append,
    )

    assert first.alerts == ()
    assert [alert.kind for alert in second.alerts] == ["health_failure"]
    assert third.alerts == ()
    assert recovered.health_ok is True
    assert after_reset.alerts == ()
    assert [alert.kind for alert in alerted_again.alerts] == ["health_failure"]
    assert len(sent) == 2
    assert all("health check failed 2 consecutive times" in message for message in sent)


def test_health_failure_without_webhook_fails_closed_at_threshold(tmp_path):
    config = _config(
        tmp_path,
        health_url="https://credentials.garz.ai/healthz",
        health_failure_threshold=1,
    )

    with pytest.raises(RuntimeError, match="no Discord webhook URL"):
        run_monitor_once(
            config,
            now=datetime(2026, 6, 12, 10, 0, tzinfo=UTC),
            journal_lines=[],
            health_checker=lambda _url: False,
        )


def test_cli_refuses_missing_journal_source(tmp_path, capsys):
    from github_credential_broker.audit_monitor import main

    with pytest.raises(SystemExit):
        main(
            [
                "--archive-dir",
                str(tmp_path / "archive"),
                "--state-file",
                str(tmp_path / "state.json"),
            ]
        )

    captured = capsys.readouterr()
    assert "one of --ssh-target or --journal-file is required" in captured.err

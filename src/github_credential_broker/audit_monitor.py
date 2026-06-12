from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

BROKER_AUDIT_PREFIX = "broker_audit "
DEFAULT_UNIT = "github-credential-broker.service"
DEFAULT_HEALTH_URL = "https://credentials.garz.ai/healthz"
DEFAULT_WEBHOOK_ENV = "BROKER_AUDIT_DISCORD_WEBHOOK_URL"
DENIAL_EVENTS = frozenset({"authentication_denied", "authorization_denied", "rate_limited"})


@dataclass(frozen=True)
class MonitorConfig:
    archive_dir: Path
    state_file: Path
    ssh_target: str | None = None
    journal_file: Path | None = None
    unit: str = DEFAULT_UNIT
    health_url: str | None = DEFAULT_HEALTH_URL
    discord_webhook_url: str | None = None
    denial_threshold: int = 5
    health_failure_threshold: int = 3
    default_since: str = "24 hours ago"


@dataclass(frozen=True)
class Alert:
    kind: str
    message: str


@dataclass(frozen=True)
class MonitorResult:
    archived_events: int
    denial_events: int
    health_ok: bool | None
    alerts: tuple[Alert, ...]


@dataclass
class MonitorState:
    journal_since: str | None = None
    consecutive_health_failures: int = 0
    health_alert_active: bool = False


AlertSender = Callable[[str], None]
HealthChecker = Callable[[str], bool]


def parse_broker_audit_line(line: str) -> dict[str, Any] | None:
    """Return one sanitized broker audit payload from a journald line."""
    _, marker, payload_text = line.partition(BROKER_AUDIT_PREFIX)
    if not marker:
        return None
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("event"), str):
        return None
    return payload


def run_monitor_once(
    config: MonitorConfig,
    *,
    now: datetime | None = None,
    journal_lines: Iterable[str] | None = None,
    health_checker: HealthChecker | None = None,
    alert_sender: AlertSender | None = None,
) -> MonitorResult:
    observed_at = (now or datetime.now(UTC)).replace(microsecond=0)
    observed_at_text = observed_at.isoformat().replace("+00:00", "Z")
    state = _load_state(config.state_file)
    since = state.journal_since or config.default_since

    lines = (
        list(journal_lines)
        if journal_lines is not None
        else _read_remote_journal(config, since, observed_at_text)
    )
    events = [
        _normalize_event(event, observed_at=observed_at_text)
        for line in lines
        if (event := parse_broker_audit_line(line)) is not None
    ]
    archive_path = _archive_events(config.archive_dir, events, observed_at=observed_at)
    state.journal_since = observed_at_text

    alerts: list[Alert] = []
    denial_count = sum(1 for event in events if event.get("event") in DENIAL_EVENTS)
    if denial_count >= config.denial_threshold:
        alerts.append(_denial_burst_alert(events, denial_count, archive_path))

    health_ok: bool | None = None
    if config.health_url:
        checker = health_checker or check_healthz
        health_ok = checker(config.health_url)
        health_alert = _update_health_state(
            state,
            health_ok=health_ok,
            threshold=config.health_failure_threshold,
            health_url=config.health_url,
        )
        if health_alert is not None:
            alerts.append(health_alert)

    if alerts:
        sender = alert_sender or _configured_alert_sender(config)
        for alert in alerts:
            sender(alert.message)

    _save_state(config.state_file, state)
    return MonitorResult(
        archived_events=len(events),
        denial_events=denial_count,
        health_ok=health_ok,
        alerts=tuple(alerts),
    )


def check_healthz(url: str, *, timeout_seconds: float = 10.0) -> bool:
    request = Request(
        url,
        method="GET",
        headers={"User-Agent": "github-credential-broker-audit-monitor"},
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return 200 <= response.status < 300
    except (OSError, URLError):
        return False


def post_discord_webhook(webhook_url: str, message: str, *, timeout_seconds: float = 10.0) -> None:
    body = json.dumps({"content": message}).encode("utf-8")
    request = Request(
        webhook_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "github-credential-broker-audit-monitor",
        },
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        if response.status >= 400:
            raise RuntimeError(f"Discord webhook returned HTTP {response.status}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Pull sanitized broker_audit records off the broker host, archive them as JSONL, "
            "and send Discord alerts for denial bursts or sustained health failures."
        )
    )
    parser.add_argument(
        "--ssh-target",
        help="SSH target that can run sudo journalctl on the broker host.",
    )
    parser.add_argument(
        "--journal-file",
        type=Path,
        help="Read journald output from a local file instead of SSH. Intended for drills/tests.",
    )
    parser.add_argument("--unit", default=DEFAULT_UNIT, help="Systemd unit to read from journald.")
    parser.add_argument("--archive-dir", type=Path, required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--health-url", default=DEFAULT_HEALTH_URL)
    parser.add_argument("--disable-health-check", action="store_true")
    parser.add_argument("--denial-threshold", type=int, default=5)
    parser.add_argument("--health-failure-threshold", type=int, default=3)
    parser.add_argument("--default-since", default="24 hours ago")
    parser.add_argument(
        "--discord-webhook-url",
        default=os.environ.get(DEFAULT_WEBHOOK_ENV),
        help=f"Discord webhook URL. Defaults to ${DEFAULT_WEBHOOK_ENV}.",
    )
    args = parser.parse_args(argv)

    if args.ssh_target and args.journal_file:
        parser.error("provide either --ssh-target or --journal-file, not both")
    if not args.ssh_target and not args.journal_file:
        parser.error("one of --ssh-target or --journal-file is required")
    if args.denial_threshold < 1:
        parser.error("--denial-threshold must be at least 1")
    if args.health_failure_threshold < 1:
        parser.error("--health-failure-threshold must be at least 1")

    config = MonitorConfig(
        archive_dir=args.archive_dir,
        state_file=args.state_file,
        ssh_target=args.ssh_target,
        journal_file=args.journal_file,
        unit=args.unit,
        health_url=None if args.disable_health_check else args.health_url,
        discord_webhook_url=args.discord_webhook_url,
        denial_threshold=args.denial_threshold,
        health_failure_threshold=args.health_failure_threshold,
        default_since=args.default_since,
    )
    result = run_monitor_once(config)
    print(
        json.dumps(
            {
                "archived_events": result.archived_events,
                "denial_events": result.denial_events,
                "health_ok": result.health_ok,
                "alerts": [alert.kind for alert in result.alerts],
            },
            sort_keys=True,
        )
    )
    return 0


def _read_remote_journal(config: MonitorConfig, since: str, until: str) -> list[str]:
    if config.journal_file is not None:
        return config.journal_file.read_text(encoding="utf-8").splitlines()
    if not config.ssh_target:
        raise ValueError("ssh_target is required when journal_file is not configured")
    command = [
        "ssh",
        config.ssh_target,
        "sudo",
        "journalctl",
        "-u",
        config.unit,
        "--since",
        since,
        "--until",
        until,
        "--no-pager",
        "-o",
        "short-iso",
    ]
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    return completed.stdout.splitlines()


def _normalize_event(event: dict[str, Any], *, observed_at: str) -> dict[str, Any]:
    normalized = dict(event)
    normalized["archived_at"] = observed_at
    return normalized


def _archive_events(
    archive_dir: Path,
    events: list[dict[str, Any]],
    *,
    observed_at: datetime,
) -> Path:
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"broker-audit-{observed_at:%Y-%m-%d}.jsonl"
    if not events:
        archive_path.touch(exist_ok=True)
        return archive_path
    with archive_path.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
    return archive_path


def _denial_burst_alert(
    events: list[dict[str, Any]],
    denial_count: int,
    archive_path: Path,
) -> Alert:
    event_counts = Counter(
        str(event.get("event")) for event in events if event.get("event") in DENIAL_EVENTS
    )
    failure_counts = Counter(
        str(event.get("failure_class"))
        for event in events
        if event.get("event") in DENIAL_EVENTS and event.get("failure_class")
    )
    event_summary = ", ".join(f"{name}={count}" for name, count in sorted(event_counts.items()))
    failure_summary = (
        ", ".join(f"{name}={count}" for name, count in sorted(failure_counts.items())) or "none"
    )
    return Alert(
        kind="denial_burst",
        message=(
            "github-credential-broker denial burst detected: "
            f"{denial_count} denied/rate-limited audit events in the latest off-host export. "
            f"events: {event_summary}. failure_classes: {failure_summary}. "
            f"archive: {archive_path}"
        ),
    )


def _update_health_state(
    state: MonitorState,
    *,
    health_ok: bool,
    threshold: int,
    health_url: str,
) -> Alert | None:
    if health_ok:
        state.consecutive_health_failures = 0
        state.health_alert_active = False
        return None
    state.consecutive_health_failures += 1
    if state.consecutive_health_failures < threshold or state.health_alert_active:
        return None
    state.health_alert_active = True
    return Alert(
        kind="health_failure",
        message=(
            "github-credential-broker health check failed "
            f"{state.consecutive_health_failures} consecutive times: {health_url}"
        ),
    )


def _configured_alert_sender(config: MonitorConfig) -> AlertSender:
    if not config.discord_webhook_url:
        raise RuntimeError(
            "alert triggered but no Discord webhook URL was configured; "
            f"set {DEFAULT_WEBHOOK_ENV} or pass --discord-webhook-url"
        )
    return lambda message: post_discord_webhook(config.discord_webhook_url or "", message)


def _load_state(path: Path) -> MonitorState:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return MonitorState()
    if not isinstance(raw, dict):
        return MonitorState()
    return MonitorState(
        journal_since=(
            raw.get("journal_since") if isinstance(raw.get("journal_since"), str) else None
        ),
        consecutive_health_failures=(
            raw["consecutive_health_failures"]
            if isinstance(raw.get("consecutive_health_failures"), int)
            and raw["consecutive_health_failures"] >= 0
            else 0
        ),
        health_alert_active=bool(raw.get("health_alert_active")),
    )


def _save_state(path: Path, state: MonitorState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "journal_since": state.journal_since,
        "consecutive_health_failures": state.consecutive_health_failures,
        "health_alert_active": state.health_alert_active,
    }
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(path)


if __name__ == "__main__":
    raise SystemExit(main())

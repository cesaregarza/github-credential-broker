#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/deploy-policy.sh POLICY_FILE [REMOTE]

Deploy a broker policy over SSH/Tailscale without rebuilding the container.

Arguments:
  POLICY_FILE  Local policy YAML file to deploy.
  REMOTE       SSH target. Defaults to BROKER_POLICY_REMOTE or
               brokeradmin@github-credential-broker-prod.

Environment:
  BROKER_POLICY_REMOTE       Default SSH target.
  BROKER_POLICY_REMOTE_PATH  Remote policy path.
                             Default: /etc/github-credential-broker/policy.yml
  BROKER_POLICY_SERVICE      Remote systemd service.
                             Default: github-credential-broker.service
  BROKER_POLICY_HEALTH_URL   Remote health URL.
                             Default: http://127.0.0.1:8080/healthz

The remote host must already be reachable by SSH. No secrets are read or stored
by this script.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 2
fi

policy_file=$1
remote=${2:-${BROKER_POLICY_REMOTE:-brokeradmin@github-credential-broker-prod}}
remote_policy_path=${BROKER_POLICY_REMOTE_PATH:-/etc/github-credential-broker/policy.yml}
remote_service=${BROKER_POLICY_SERVICE:-github-credential-broker.service}
remote_health_url=${BROKER_POLICY_HEALTH_URL:-http://127.0.0.1:8080/healthz}

if [[ ! -f "$policy_file" ]]; then
  echo "policy file does not exist: $policy_file" >&2
  exit 1
fi

ssh_opts=(-o StrictHostKeyChecking=accept-new)
scp_opts=(-o StrictHostKeyChecking=accept-new)

echo "Validating local policy: $policy_file"
if command -v uv >/dev/null 2>&1 && [[ -f pyproject.toml ]]; then
  uv run github-credential-broker-validate-policy "$policy_file"
else
  python3 - "$policy_file" <<'PY'
from pathlib import Path
import sys

from github_credential_broker.policy import load_policy

policy = load_policy(Path(sys.argv[1]))
print(
    f"policy valid: {sys.argv[1]} "
    f"({len(policy.capabilities)} capabilities, {len(policy.grants)} grants)"
)
PY
fi

echo "Creating remote staging directory on $remote"
remote_tmp=$(ssh "${ssh_opts[@]}" "$remote" 'mktemp -d /tmp/github-credential-broker-policy.XXXXXX')

cleanup() {
  ssh "${ssh_opts[@]}" "$remote" "rm -rf '$remote_tmp'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Uploading candidate policy"
scp "${scp_opts[@]}" "$policy_file" "$remote:$remote_tmp/policy.yml" >/dev/null

echo "Validating, installing, and restarting broker on $remote"
ssh "${ssh_opts[@]}" "$remote" bash -s -- \
  "$remote_tmp/policy.yml" \
  "$remote_policy_path" \
  "$remote_service" \
  "$remote_health_url" <<'REMOTE'
set -euo pipefail

candidate=$1
remote_policy_path=$2
remote_service=$3
remote_health_url=$4

image=$(sudo docker inspect github-credential-broker --format '{{.Config.Image}}' 2>/dev/null || true)
if [[ -z "$image" ]]; then
  echo "could not determine running broker image from container github-credential-broker" >&2
  exit 1
fi

echo "Remote validating policy with image: $image"
sudo docker run --rm \
  --entrypoint python \
  -v "$candidate:/tmp/policy.yml:ro" \
  "$image" \
  -c 'from pathlib import Path; from github_credential_broker.policy import load_policy; p = load_policy(Path("/tmp/policy.yml")); print(f"policy valid: /tmp/policy.yml ({len(p.capabilities)} capabilities, {len(p.grants)} grants)")'

backup=""
if sudo test -f "$remote_policy_path"; then
  backup="${remote_policy_path}.$(date -u +%Y%m%dT%H%M%SZ).bak"
  sudo cp -a "$remote_policy_path" "$backup"
  echo "Backed up current policy to $backup"
fi

rollback() {
  if [[ -n "$backup" ]] && sudo test -f "$backup"; then
    echo "Rolling back to $backup" >&2
    sudo cp -a "$backup" "$remote_policy_path"
    sudo systemctl restart "$remote_service" || true
  fi
}

sudo install -o root -g root -m 0644 "$candidate" "$remote_policy_path"

if ! sudo systemctl restart "$remote_service"; then
  rollback
  exit 1
fi

for attempt in $(seq 1 15); do
  if curl -fsS "$remote_health_url" >/tmp/github-credential-broker-health.out; then
    cat /tmp/github-credential-broker-health.out
    echo
    echo "Policy deployed and broker health check passed"
    exit 0
  fi
  sleep 2
done

echo "broker health check failed after policy deploy" >&2
rollback
exit 1
REMOTE

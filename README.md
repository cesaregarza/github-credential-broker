# GitHub Credential Broker

Small HTTPS service for issuing deployment credentials to GitHub Actions jobs
after verifying GitHub OIDC identity claims.

The broker is meant to reduce repeated GitHub repository secrets without moving
those secrets into reusable workflow repositories. Caller repositories store no
vault token. They request a GitHub OIDC token and present it to this broker.

## Security Model

- Deny by default.
- Authenticate every request with a GitHub Actions OIDC JWT.
- Validate issuer, audience, signature, and expiry.
- Authorize against explicit policy claims such as `repository`, `ref`,
  `environment`, `workflow_ref`, and `job_workflow_ref`.
- Resolve credential values from the broker deployment environment or a
  dedicated 1Password vault.
- Never log secret values.

## Request Flow

```text
GitHub Actions job
  -> requests OIDC token for the broker's deployment-specific audience
  -> POST /v1/capabilities with requested capability names
  -> broker validates token and policy
  -> broker returns only the requested secrets allowed by matching grants
```

## Quick Start

1. Pick a public HTTPS broker URL and OIDC audience for your deployment.
   Examples below use `https://broker.example.com` and
   `https://broker.example.com/v1`.
2. Store real credential values either in the broker host environment or in a
   dedicated 1Password vault. Do not put vault tokens or cloud tokens in caller
   repositories.
3. Add reusable policy capabilities for real permissions, then grant those
   capabilities to exact GitHub repositories, refs, environments, and workflows.
4. Validate the policy:

   ```bash
   uv sync
   uv run github-credential-broker-validate-policy config/policy.yml
   uv run github-credential-broker-lint-policy config/policy.yml
   ```

5. Deploy the broker, then configure caller workflows with `id-token: write`
   and request credentials from `POST /v1/capabilities`.

## Current Deployment

The checked-in DigitalOcean/Terraform deployment targets the broker used by
this repo:

- URL: `https://credentials.garz.ai`
- GitHub OIDC audience: `https://credentials.garz.ai/v1`
- Credential endpoint: `POST https://credentials.garz.ai/v1/capabilities`

## Configuration

The broker is configured via environment variables prefixed with `BROKER_`.

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `BROKER_POLICY_PATH` | yes | `config/policy.yml` | Path to the policy file. |
| `BROKER_GITHUB_OIDC_AUDIENCE` | **yes** | — | Audience callers must request. **Pick a unique value per deployment** (e.g. `https://broker.example.com/v1`). A unique audience prevents both cross-broker token replay and trivial attacks where a third-party workflow mints a token for a guessable audience. |
| `BROKER_GITHUB_OIDC_ISSUER` | no | GitHub's issuer | Override only if you proxy GitHub's OIDC. |
| `BROKER_GITHUB_OIDC_JWKS_URL` | no | GitHub's JWKS | Override only if you proxy GitHub's OIDC. |
| `BROKER_REQUIRE_JTI` | no | `true` | Require GitHub OIDC `jti` and redeem each token ID only once per process until JWT expiry. |
| `BROKER_EXPOSE_DOCS` | no | `false` | Set `true` to enable `/docs` and `/openapi.json`. Do not enable in production. |
| `BROKER_ENABLE_LEGACY_CREDENTIALS` | no | `false` | Temporarily enables legacy `POST /v1/credentials/{name}` for bundle migration. |
| `BROKER_RATE_LIMIT_ENABLED` | no | `true` | Enables in-process IP and verified-identity rate limits. |
| `BROKER_RATE_LIMIT_IP_PER_MINUTE` | no | `60` | Pre-authentication requests allowed per derived client IP per minute. |
| `BROKER_RATE_LIMIT_IDENTITY_PER_MINUTE` | no | `30` | Post-authentication requests allowed per `repository_id`, `repository`, or `sub` per minute. |
| `BROKER_TRUSTED_PROXY_CIDRS` | no | empty | Comma-separated proxy CIDRs trusted for `X-Forwarded-For`; loopback peers are always trusted. |
| `BROKER_ONEPASSWORD_CLI_PATH` | no | `op` | Path to the 1Password CLI used for `op:` policy secrets. |
| `BROKER_ONEPASSWORD_READ_TIMEOUT_SECONDS` | no | `10` | Per-secret timeout for `op read`. |
| `BROKER_ONEPASSWORD_CACHE_SECONDS` | no | `60` | In-memory cache TTL for `op:` secret values. Set `0` to disable. |
| `BROKER_READINESS_CHECK_SECRET_RESOLUTION` | no | `false` | If `true`, `/readyz` verifies configured `op:` references can be read. Secret values are discarded and never returned. |

If any policy secret uses `op:`, the runtime also needs
`OP_SERVICE_ACCOUNT_TOKEN` set to a 1Password service account token that can
read only the broker vault.

The production container is read-only and runs as an unprivileged UID. Set
`HOME=/tmp` and `OP_CACHE=false` so the 1Password CLI does not try to create
state under `/home/broker`.

## Run Locally

```bash
uv sync
export BROKER_POLICY_PATH=config/policy.example.yml
export BROKER_GITHUB_OIDC_AUDIENCE="https://broker.example.com/v1"
export OP_SERVICE_ACCOUNT_TOKEN=ops_...
uv run uvicorn github_credential_broker.app:create_app --factory --host 127.0.0.1 --port 8080
```

Local credential calls need a valid GitHub OIDC token, so normal local testing
focuses on unit tests, policy validation, and direct `op://` reference checks.

## Deploy

Build a container and mount/provide a real policy file. Put runtime
configuration in a root-only env file such as
`/etc/github-credential-broker/broker.env`:

```env
BROKER_POLICY_PATH=/app/config/policy.yml
BROKER_GITHUB_OIDC_AUDIENCE=https://broker.example.com/v1
HOME=/tmp
OP_CACHE=false
OP_SERVICE_ACCOUNT_TOKEN=ops_...
```

```bash
docker build -t github-credential-broker .
docker run --rm -p 8080:8080 \
  --env-file /etc/github-credential-broker/broker.env \
  -v "$PWD/config/policy.yml:/app/config/policy.yml:ro" \
  github-credential-broker
```

For `op:` policy secrets, that env file must include `OP_SERVICE_ACCOUNT_TOKEN`.
For `env:` policy secrets, it must include the referenced secret variables.

Terraform for the DigitalOcean Droplet, Cloudflare DNS record, firewall, Caddy,
Tailscale bootstrap, and broker systemd unit lives in `infra/terraform`.

In production, also:

- Put the broker behind a reverse proxy that enforces TLS. The broker also has
  basic in-process rate limiting for this single-host deployment; keep edge
  limits in the reverse proxy if the service is exposed publicly.
- Ship audit logs to a durable sink. The broker emits compact JSON audit logs
  for issued credentials and denied authentication, authorization, replay, and
  rate-limit attempts; if the container is lost or evicted, local records are
  gone.

For production, put it behind HTTPS. The endpoint can be public because requests
are denied unless the GitHub OIDC JWT validates and matches policy, but the
service should still be treated as sensitive infrastructure.

During the capability-policy migration, the broker can still load legacy
`bundles:` policies, but `POST /v1/credentials/{name}` is disabled by default.
Set `BROKER_ENABLE_LEGACY_CREDENTIALS=true` only while actively migrating a
legacy caller, then migrate workflows to `POST /v1/capabilities` and turn the
legacy route back off.

Generated OpenAPI/Swagger docs are disabled by default. If you need them in a
non-production environment, set `BROKER_EXPOSE_DOCS=true`.

## Health and Readiness

`GET /healthz` is a cheap liveness check and returns `{"ok": true}` as long as
the app process can answer.

`GET /readyz` verifies the broker configuration is usable:

- the policy loaded successfully
- the GitHub OIDC verifier was initialized
- if the policy references `op://` secrets, the configured 1Password CLI is
  installed
- if `BROKER_READINESS_CHECK_SECRET_RESOLUTION=true`, configured `op://`
  references can be read

Readiness never returns secret values. Keep Caddy or uptime checks on
`/healthz`; use `/readyz` for deployment validation and alerts that should
catch bad policy or missing 1Password runtime setup.

## Audit Logging

The broker writes compact JSON audit records to stdout with the `broker_audit`
prefix for issued credentials and denied authentication, authorization, replay,
and rate-limit attempts. The records include request metadata, requested
capability names, failure classes, and verified safe GitHub claims when
available. They never include bearer tokens, raw JWTs, 1Password values, or
resolved secret values.

For the Terraform Droplet deployment, cloud-init enables persistent journald
storage with a bounded local retention policy. Inspect recent broker logs with:

```bash
sudo journalctl -u github-credential-broker.service -n 100 --no-pager
```

Local journald retention is not an off-host durable sink. Production operators
should export the journal to a remote system such as Vector, a managed syslog
collector, or a log platform. A minimal production recipe is:

1. Keep `/etc/systemd/journald.conf.d/github-credential-broker.conf` with
   `Storage=persistent` and bounded retention.
2. Install a host log shipper that reads journald.
3. Filter on `broker_audit` or the
   `github-credential-broker.service` systemd unit.
4. Send logs over TLS to the remote sink and set sink-side retention/alerts for
   denied authn/authz, replay, and rate-limit events.

## 1Password

For a DigitalOcean Droplet, use a dedicated 1Password vault such as
`github-credential-broker-prod` and a read-only service account scoped only to
that vault. Store the service account token on the Droplet as a root-only
runtime secret, not in GitHub and not in the image.

Policy capabilities can reference 1Password fields with `op://` references:

```yaml
capabilities:
  digitalocean-k8s-deploy:
    description: DigitalOcean credentials for Kubernetes deployment updates.
    secrets:
      DIGITALOCEAN_ACCESS_TOKEN:
        op: op://github-credential-broker-prod/digitalocean-k8s-deploy/DIGITALOCEAN_ACCESS_TOKEN
      DIGITALOCEAN_KUBERNETES_CLUSTER_ID:
        op: op://github-credential-broker-prod/digitalocean-k8s-deploy/DIGITALOCEAN_KUBERNETES_CLUSTER_ID

grants:
  - description: SplatTop deploy workflow.
    allow:
      - repository: cesaregarza/SplatTop
        repository_id: "123456789"
        ref: refs/heads/main
        environment: SplatTop
    capabilities:
      - digitalocean-k8s-deploy
```

The broker validates GitHub OIDC and policy before resolving these references.
The 1Password token is never returned to GitHub Actions.

When migrating from repo-specific policy entries, create or rename the
1Password items to match the capability paths in policy before deploying it, or
adjust the `op:` references to point at already-existing items.

## GitHub Actions Caller Example

The caller workflow must grant `id-token: write`, request the same OIDC
audience configured on the broker, and request only capability names allowed by
matching policy grants. Mask every returned secret value before writing any
derived output to the log.

```yaml
permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Request GitHub OIDC token
        id: oidc
        shell: bash
        run: |
          set -euo pipefail
          token_json="$(
            curl -sSf \
              -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
              "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=https://broker.example.com/v1"
          )"
          token="$(jq -r .value <<< "$token_json")"
          echo "::add-mask::$token"
          echo "token=$token" >> "$GITHUB_OUTPUT"

      - name: Fetch deployment credentials
        id: creds
        shell: bash
        env:
          BROKER_URL: https://broker.example.com
          OIDC_TOKEN: ${{ steps.oidc.outputs.token }}
        run: |
          set -euo pipefail
          response="$(
            jq -nc '{capabilities: ["digitalocean-k8s-deploy", "config-repo-write"]}' |
              curl -sSf -X POST \
                -H "Authorization: Bearer $OIDC_TOKEN" \
                -H "Content-Type: application/json" \
                --data-binary @- \
                "$BROKER_URL/v1/capabilities"
          )"

          while IFS= read -r secret_value; do
            if [[ -n "$secret_value" && "$secret_value" != "null" ]]; then
              echo "::add-mask::$secret_value"
            fi
          done < <(jq -r '.secrets[]' <<< "$response")

          do_token="$(jq -r '.secrets.DIGITALOCEAN_ACCESS_TOKEN' <<< "$response")"
          config_token="$(jq -r '.secrets.SPLATTOP_CONFIG_GITHUB_TOKEN' <<< "$response")"
          {
            echo "DIGITALOCEAN_ACCESS_TOKEN=$do_token"
            echo "SPLATTOP_CONFIG_GITHUB_TOKEN=$config_token"
          } >> "$GITHUB_ENV"
```

## Smoke Test

This repo includes a manual `Broker smoke test` workflow. It requests a GitHub
OIDC token, fetches the `broker-smoke-test` capability, masks the returned
value, and asserts that the non-sensitive `TEST_TOKEN` value is exactly
`test_value`.

Use it after changing broker policy or deployment wiring:

```bash
gh workflow run broker-smoke-test.yml --repo cesaregarza/github-credential-broker
```

If printing is enabled, GitHub Actions should redact the fake `TEST_TOKEN`
value because the workflow masks every returned secret value first. Do not copy
the print pattern for real credentials.

## Policy

The current checked-in deployment policy is `config/policy.yml`. A sanitized
starter policy lives at `config/policy.example.yml`.

Policy is intentionally strict:

- Capability names must match the credential request name format.
- Secret response names and `env:` source names must be shell-safe variable
  names.
- Each secret must set exactly one source: `env:` for environment variables or
  `op:` for a 1Password secret reference.
- Wildcards are only accepted in `ref`, `workflow_ref`, and
  `job_workflow_ref` grant claims. Repository and environment claims must be
  exact matches.

For high-sensitivity grants, prefer adding stable GitHub identity claims such
as `repository_id` and `repository_owner_id` alongside human-readable
`repository` and `ref` checks. Repository names and org names can be transferred
or renamed; numeric IDs cannot.

Set `strict: true` at the top of the policy file to require `repository_id` in
every allow rule. For tighter policies, use object form to require any stable
claims everywhere:

```yaml
strict:
  required_claims:
    - repository_id
    - repository_owner_id
```

The broker will refuse to start if any allow rule is missing a required claim.
Capabilities can also declare their own `required_claims`; every grant that
references that capability must include those claims in each allow rule.

For reusable workflows, prefer adding `job_workflow_ref` to policy rules once
the caller repos migrate to `cesaregarza/.github`, for example:

```yaml
grants:
  - allow:
      - repository: cesaregarza/SplatTop
        repository_id: "123456789"
        repository_owner_id: "987654321"
        ref: refs/heads/main
        environment: SplatTop
        job_workflow_ref: cesaregarza/.github/.github/workflows/docker-build-docr.yml@refs/heads/main
        job_workflow_sha: 0123456789abcdef0123456789abcdef01234567
    capabilities:
      - digitalocean-k8s-deploy
```

Add new capabilities for reusable permission boundaries, then add grants with
the narrowest claims that still match the intended workflow. A typical
production policy entry looks like this:

```yaml
capabilities:
  digitalocean-k8s-deploy:
    description: DigitalOcean credentials for Kubernetes deployment updates.
    required_claims:
      - repository_id
      - repository_owner_id
      - ref
      - environment
      - job_workflow_ref
    secrets:
      DIGITALOCEAN_ACCESS_TOKEN:
        op: op://github-credential-broker-prod/digitalocean-k8s-deploy/DIGITALOCEAN_ACCESS_TOKEN

grants:
  - description: my-app deploy workflow.
    allow:
      - repository: owner/my-app
        repository_id: "123456789"
        repository_owner_id: "987654321"
        ref: refs/heads/main
        environment: production
        workflow_ref: owner/my-app/.github/workflows/deploy.yml@refs/heads/main
        job_workflow_ref: owner/.github/.github/workflows/deploy.yml@refs/heads/main
        job_workflow_sha: 0123456789abcdef0123456789abcdef01234567
    capabilities:
      - digitalocean-k8s-deploy
```

Use `env:` instead of `op:` only when the secret is present in the broker
service env file on the Droplet.

Run the policy linter before deploying broad policy changes:

```bash
uv run github-credential-broker-lint-policy config/policy.yml
uv run github-credential-broker-lint-policy --strict config/policy.yml
```

By default the linter exits 0 and prints warnings. Use `--strict` in CI or
pre-deploy checks when warnings should block. It reports missing stable GitHub
IDs, production-looking grants without environments, wildcard refs/workflows,
broad rules that grant multiple high-risk capabilities, and capability names
that share the same 1Password item path.

Deploy policy changes over Tailscale SSH without rebuilding the image:

```bash
scripts/deploy-policy.sh config/policy.yml
```

If MagicDNS is not available in your shell, pass the Tailscale IP explicitly:

```bash
scripts/deploy-policy.sh config/policy.yml brokeradmin@100.97.170.7
```

The script validates the policy locally, uploads it to a temporary path on the
Droplet, validates it again using the running broker image, installs it
atomically with a timestamped backup, restarts the broker, and checks
`/healthz`. It assumes SSH access is already available in your shell.

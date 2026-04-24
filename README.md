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
- Resolve credential values from the broker deployment environment.
- Never log secret values.

## Request Flow

```text
GitHub Actions job
  -> requests OIDC token for audience github-credential-broker
  -> POST /v1/credentials/{bundle}
  -> broker validates token and policy
  -> broker returns only the allowed secret bundle
```

## Run Locally

```bash
uv sync
export BROKER_POLICY_PATH=config/policy.example.yml
export SPLATTOP_DO_TOKEN=dummy
export SPLATTOP_CONFIG_REPO_TOKEN=dummy
uv run uvicorn github_credential_broker.app:create_app --factory --host 127.0.0.1 --port 8080
```

Local calls need a valid GitHub OIDC token, so normal local testing focuses on
unit tests and policy validation.

## Deploy

Build a container and mount/provide a real policy file plus environment-backed
secret values:

```bash
docker build -t github-credential-broker .
docker run --rm -p 8080:8080 \
  -e BROKER_POLICY_PATH=/app/config/policy.yml \
  -e SPLATTOP_DO_TOKEN=... \
  -e SPLATTOP_CONFIG_REPO_TOKEN=... \
  -v "$PWD/config/policy.example.yml:/app/config/policy.yml:ro" \
  github-credential-broker
```

For production, put it behind HTTPS. The endpoint can be public because requests
are denied unless the GitHub OIDC JWT validates and matches policy, but the
service should still be treated as sensitive infrastructure.

## GitHub Actions Caller Example

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
              "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=github-credential-broker"
          )"
          token="$(jq -r .value <<< "$token_json")"
          echo "::add-mask::$token"
          echo "token=$token" >> "$GITHUB_OUTPUT"

      - name: Fetch deployment credentials
        id: creds
        shell: bash
        env:
          BROKER_URL: https://credentials.example.com
          OIDC_TOKEN: ${{ steps.oidc.outputs.token }}
        run: |
          set -euo pipefail
          response="$(
            curl -sSf -X POST \
              -H "Authorization: Bearer $OIDC_TOKEN" \
              "$BROKER_URL/v1/credentials/splattop-deploy"
          )"
          do_token="$(jq -r '.secrets.DIGITALOCEAN_ACCESS_TOKEN' <<< "$response")"
          config_token="$(jq -r '.secrets.CONFIG_REPO_TOKEN' <<< "$response")"
          echo "::add-mask::$do_token"
          echo "::add-mask::$config_token"
          {
            echo "DIGITALOCEAN_ACCESS_TOKEN=$do_token"
            echo "CONFIG_REPO_TOKEN=$config_token"
          } >> "$GITHUB_ENV"
```

## Policy

See `config/policy.example.yml`.

For reusable workflows, prefer adding `job_workflow_ref` to policy rules once
the caller repos migrate to `cesaregarza/.github`, for example:

```yaml
allow:
  - repository: cesaregarza/SplatTop
    ref: refs/heads/main
    environment: SplatTop
    job_workflow_ref: cesaregarza/.github/.github/workflows/docker-build-docr.yml@refs/heads/main
```

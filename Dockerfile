FROM python:3.12-slim

ARG TARGETARCH=amd64

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

RUN groupadd --system --gid 10001 broker \
    && useradd --system --uid 10001 --gid broker --home-dir /home/broker --create-home --shell /usr/sbin/nologin broker \
    && case "$TARGETARCH" in amd64|arm64) ;; *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; esac \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://downloads.1password.com/linux/keys/1password.asc --output /tmp/1password.asc \
    && gpg --dearmor --output /etc/apt/keyrings/1password-archive-keyring.gpg /tmp/1password.asc \
    && echo "deb [arch=${TARGETARCH} signed-by=/etc/apt/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/${TARGETARCH} stable main" \
        > /etc/apt/sources.list.d/1password.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends 1password-cli \
    && apt-get purge -y --auto-remove curl gnupg \
    && rm -f /tmp/1password.asc \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir uv==0.8.17

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY config ./config

RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH" \
    HOME=/home/broker \
    BROKER_POLICY_PATH=/app/config/policy.yml

EXPOSE 8080

USER broker

CMD ["uvicorn", "github_credential_broker.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]

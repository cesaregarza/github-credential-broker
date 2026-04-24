FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

RUN groupadd --system --gid 10001 broker \
    && useradd --system --uid 10001 --gid broker --home-dir /app --no-create-home --shell /usr/sbin/nologin broker \
    && python -m pip install --no-cache-dir uv==0.8.17

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY config ./config

RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH" \
    BROKER_POLICY_PATH=/app/config/policy.yml

EXPOSE 8080

USER broker

CMD ["uvicorn", "github_credential_broker.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]

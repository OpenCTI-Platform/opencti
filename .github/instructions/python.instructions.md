---
applyTo: "client-python/**, opencti-worker/**"
description: "Python client, worker, and automation guidelines"
---

# Python (client-python & opencti-worker)

## Scope
This guide covers:
- `client-python`: The official OpenCTI Python SDK (`pycti`).
- `opencti-worker`: Background worker implementation (Python-based).
- Automation scripts & tooling.

## Architecture

### Tech Stack
- **Python**: 3.10 to 3.12 (Matrix tested)
- **Library**: `pycti`
- **Linting**: flake8, black, isort
- **Testing**: pytest

### Project Structure
- The Python projects form a [uv](https://docs.astral.sh/uv/) workspace: `pyproject.toml` and `uv.lock` at the repository root, one `.venv` shared by the members.
- `client-python/src/pycti/`: source code package, `examples/`: sample scripts, `tests/`: pytest suite (requires a running OpenCTI instance). Dependencies and dependency groups (`test`, `lint`, `doc`) in `client-python/pyproject.toml`.
- `opencti-worker/src/opencti_worker/`: worker package, entry point `opencti-worker`. Dependencies in `opencti-worker/pyproject.toml`.
- `opencti-platform/opencti-graphql/src/python/`: Python runtime embedded in the platform, dependencies in its `pyproject.toml`.

## Setup & Build

### Prerequisites
- **uv** (standalone installer), it downloads the Python version pinned in `.python-version` when needed.

### Commands

**Client Python (pycti)**:
```bash
uv sync --package pycti          # pycti, its dependencies and the dev groups in .venv

cd client-python
# Quality Checks
uv run flake8 . --ignore E,W     # Check style
uv run black .                   # Format code
uv run isort .                   # Organize imports

# Testing
# Requires running OpenCTI instance (OPENCTI_URL, OPENCTI_TOKEN env vars)
uv run pytest --cov=pycti --no-header -vv
```

**Worker**:
```bash
uv sync --package opencti-worker
# Set ENV: OPENCTI_URL, OPENCTI_TOKEN, WORKER_LOG_LEVEL=INFO
uv run --package opencti-worker opencti-worker
uv run --package opencti-worker pytest opencti-worker/tests
```

Dependencies are added with `uv add --package <member> <dependency>`, never by editing `uv.lock`. CI and Docker install with `uv sync --locked`, so `uv.lock` must be committed with every `pyproject.toml` change.

## Implementation Patterns

### 1. Code Style (Strict)
- Use **black** for formatting (mandatory).
- Use **isort** for imports.
- Use **flake8** for linting.

### 2. PyCTI Usage
- Always handle API exceptions gracefully.
- Use pagination helpers for large datasets.
- Prefer bulk operations where available.

### 3. Worker Logic
- Keep worker tasks idempotent.
- Handle connection retries (RabbitMQ/Redis) robustly.
- Log meaningful context (Worker ID, Job ID).

## Common Issues
- **Import Errors**: Ensure you ran `uv sync` and run commands through `uv run`.
- **Connection Refused**: Check if OpenCTI API is reachable.
- **SSL/TLS**: Verify certificate validation settings (`verify=True/False`).

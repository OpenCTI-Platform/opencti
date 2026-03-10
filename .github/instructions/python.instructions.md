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

### Project Structure (client-python)
- `pycti/`: Source code package
- `examples/`: Sample scripts
- `tests/`: Pytest suite (requires running OpenCTI instance)
- `requirements.txt`: Prod dependencies
- `test-requirements.txt`: Test/Dev dependencies

## Setup & Build

### Prerequisites
- **Python 3.10+**
- **pip** and **virtualenv** recommended.

### Commands

**Client Python (pycti)**:
```bash
cd client-python
pip3 install -r requirements.txt
pip3 install -r test-requirements.txt
pip3 install -e .[dev,doc]     # Editable install

# Quality Checks
flake8 . --ignore E,W          # Check style
black .                        # Format code
isort .                        # Organize imports

# Testing
# Requires running OpenCTI instance (OPENCTI_URL, OPENCTI_TOKEN env vars)
python3 -m pytest --cov=pycti --no-header -vv
```

**Worker**:
```bash
cd opencti-worker
pip3 install -r src/requirements.txt
# Set ENV: OPENCTI_URL, OPENCTI_TOKEN, WORKER_LOG_LEVEL=INFO
python3 src/worker.py
```

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
- **Import Errors**: Ensure you installed in editable mode (`-e .`) or site-packages.
- **Connection Refused**: Check if OpenCTI API is reachable.
- **SSL/TLS**: Verify certificate validation settings (`verify=True/False`).

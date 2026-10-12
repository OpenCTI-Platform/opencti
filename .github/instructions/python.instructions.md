---
applyTo: "client-python/**, opencti-worker/**, opencti-analytics/**"
description: "Python client, worker, analytics process and automation guidelines"
---

# Python (client-python, opencti-worker & opencti-analytics)

## Scope
This guide covers:
- `client-python`: The official OpenCTI Python SDK (`pycti`).
- `opencti-worker`: Background worker implementation (Python-based).
- `opencti-analytics`: Optional graph analytics process (communities, clusters, approximate betweenness).
- Automation scripts & tooling.

## Architecture

### Tech Stack
- **Python**: 3.10 to 3.12 (Matrix tested); `opencti-analytics` requires 3.12 or later
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
pip3 install -r requirements.txt
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

### 4. Analytics process
- The process only reads ids and types (`graphAnalyticsEdges`) and only writes through
  `graphAnalyticsUpsertMetrics`: it never creates or modifies STIX objects or relationships.
- Results must be deterministic for the same graph (seeded algorithms, sorted inputs, cluster ids derived
  from the cluster content) so clusters keep their identity and their promotions across runs.
- Respect the platform write-back limits (5000 metrics, 1000 clusters per call) and complete each run with
  `complete: true` so older assignments are detached.
- Tests run without a platform (`python -m pytest` in `opencti-analytics`), the API client is faked.

## Common Issues
- **Import Errors**: Ensure you installed in editable mode (`-e .`) or site-packages.
- **Connection Refused**: Check if OpenCTI API is reachable.
- **SSL/TLS**: Verify certificate validation settings (`verify=True/False`).

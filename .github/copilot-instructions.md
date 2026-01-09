# OpenCTI Copilot Instructions

## Repository Overview

OpenCTI is a cyber threat intelligence platform built with a **monorepo structure** containing:
- **opencti-platform/opencti-graphql**: Node.js/TypeScript GraphQL API backend (~60MB)
- **opencti-platform/opencti-front**: React/TypeScript frontend with Relay (~50MB)
- **client-python**: Python library (pycti) for API access (~17MB)
- **opencti-worker**: Python worker for background tasks
- **docs**: MkDocs documentation (~56MB)

**Tech Stack**: Node.js ≥20, Python 3.9-3.12, Yarn 4.12.0, TypeScript, React 19, GraphQL, ElasticSearch/OpenSearch, Redis, RabbitMQ, MinIO

## Critical Build Requirements

### Enable Corepack First
**CRITICAL**: Before any yarn commands, enable corepack to use Yarn 4.12.0:
```bash
corepack enable                 # One-time setup, downloads correct Yarn version
```

### ALWAYS Copy .yarnrc.yml First
**Before any `yarn` command**, copy `.yarnrc.yml` from `opencti-platform/` to the working directory:
```bash
cd opencti-platform/opencti-graphql  # or opencti-front
cp ../.yarnrc.yml .yarnrc.yml
yarn install
```
**Why**: The `.yarnrc.yml` enforces security policies (disables scripts, 4320-min package age gate) and pinned versions. Commands will fail or behave unexpectedly without it.

### Backend (opencti-graphql)

**Install & Build**:
```bash
cd opencti-platform/opencti-graphql
cp ../.yarnrc.yml .yarnrc.yml
yarn install                    # ~5 min first time
yarn install:python             # Python deps: pip3 install -r src/python/requirements.txt
yarn build:prod                 # Production build (~3 min)
# OR: yarn build:dev            # Dev build with schema (~2 min)
```

**Linting & Type Checking**:
```bash
yarn check-ts                   # TypeScript (~30s)
yarn lint                       # ESLint (~45s)
```

**Testing** (requires Docker):
```bash
yarn test:ci-unit              # Unit tests (~2 min)
yarn test:ci-integration-sync  # Integration tests (~10-15 min)
yarn test:ci-rules-and-others  # Rules/TAXII tests (~8 min)
```

**Common Issues**:
- **Missing Python deps**: Run `yarn install:python` after `yarn install`
- **Build timeout**: Use `NODE_OPTIONS=--max_old_space_size=8192`
- **Schema errors**: Run `yarn build:schema`
- **"Cannot find module opencti-manifest.json"**: Run `yarn get-connectors-manifest`

### Frontend (opencti-front)

**Install & Build**:
```bash
cd opencti-platform/opencti-front
cp ../.yarnrc.yml .yarnrc.yml
yarn install                    # ~4 min
yarn relay                      # Generate Relay artifacts (~1 min)
yarn build                      # Production build (~5 min)
```

**Linting & Type Checking**:
```bash
yarn check-ts                   # TypeScript (~40s)
yarn lint                       # ESLint (~30s)
```

**Testing**:
```bash
yarn test                       # Unit tests with Vitest (~2 min)
yarn test:coverage              # With coverage (~3 min)
yarn test:e2e                   # E2E Playwright tests (~10 min, needs full stack)
node script/verify-translation.js  # Translation validation (runs in CI)
```

### Client Python (pycti)

**Setup & Test**:
```bash
cd client-python
pip3 install -r requirements.txt
pip3 install -r test-requirements.txt
pip3 install -e .[dev,doc]     # Editable install

# Linting: flake8 . (ignore E,W), black ., isort .
# Testing: python3 -m pytest --cov=pycti --no-header -vv (requires OpenCTI instance)
```

### Worker

**Setup**:
```bash
cd opencti-worker
pip3 install -r src/requirements.txt
# Requires: OPENCTI_URL and OPENCTI_TOKEN environment variables
python3 src/worker.py           # Start worker
```

## CI/CD Workflows

**Main CI** (`.github/workflows/ci-main.yml`) runs on all PRs:
1. **Docker Build**: Builds platform & worker images (~10 min)
2. **API Tests**: Integration, rules, and unit tests (~20 min) - requires Docker backend services
3. **Frontend Tests**: Unit tests (~5 min), E2E tests (~15 min), translation validation
4. **Client Python**: Matrix tests for Python 3.9-3.12 (~10 min each)
5. **License Check**: Verifies allowed licenses (~5 min)

**All commits MUST be GPG signed** (`check-verified-commit.yml` enforces this).

## Local Development Setup

**Prerequisites**: Node.js ≥20, Python 3.9-3.12, Docker, `corepack enable`, `sudo sysctl -w vm.max_map_count=262144`

**Start Infrastructure**:
```bash
cd opencti-platform/opencti-dev
docker compose up -d  # Elasticsearch (9200), Redis (6379), RabbitMQ, MinIO, Kibana
```

**Backend**: `cd opencti-platform/opencti-graphql`, copy `.yarnrc.yml`, edit `config/development.json`, run `yarn install && yarn install:python && yarn start`

**Frontend**: `cd opencti-platform/opencti-front`, copy `.yarnrc.yml`, run `yarn install && yarn start` → http://localhost:3000

## Project Structure

```
opencti/
├── opencti-platform/
│   ├── .yarnrc.yml             # Yarn config - MUST copy to subdirs
│   ├── opencti-graphql/        # Backend API
│   │   ├── src/                # TypeScript source
│   │   ├── config/             # JSON configs (default.json, test.json)
│   │   ├── tests/              # Vitest test suites
│   │   ├── vitest.config.*.ts  # Test configs (ci-unit, ci-integration, dev)
│   │   ├── eslint.config.mjs   # ESLint v9 flat config
│   │   └── tsconfig.json
│   ├── opencti-front/          # Frontend SPA
│   │   ├── src/                # React/TypeScript source
│   │   ├── tests_e2e/          # Playwright E2E tests
│   │   ├── lang/               # i18n translation files
│   │   ├── relay.config.json   # Relay compiler config
│   │   └── playwright.config.ts
│   └── opencti-dev/
│       └── docker-compose.yml  # Dev infrastructure
├── client-python/
│   ├── pycti/                  # Main library code
│   ├── tests/                  # Pytest tests
│   ├── pyproject.toml          # Python package config
│   └── .flake8, .isort.cfg     # Linting configs
├── opencti-worker/
│   └── src/
│       ├── worker.py
│       └── requirements.txt
├── scripts/ci/
│   ├── docker-compose.yml      # CI test infrastructure
│   └── ci-common.env           # CI environment variables
└── .pre-commit-config.yaml     # Pre-commit hooks (isort, black, eslint)
```

## Key Configuration Files

- **ESLint**: `eslint.config.mjs` (v9 flat config), **TypeScript**: `tsconfig.json` (strict mode)
- **Vitest**: Multiple configs (ci-unit, ci-integration, dev), **Python**: `.flake8`, `.isort.cfg`, `pyproject.toml`

## Common Pitfalls & Solutions

1. **Yarn command fails**: Missing `.yarnrc.yml` - ALWAYS copy it first
2. **"Module not found" errors**: Run `yarn install:python` for backend, check Relay artifacts for frontend
3. **Test failures in CI**: Local tests pass but CI fails → Check Docker service health, increase timeouts
4. **Build out of memory**: Add `NODE_OPTIONS=--max_old_space_size=8192` before yarn commands
5. **ElasticSearch won't start**: Run `sudo sysctl -w vm.max_map_count=262144`
6. **Unsigned commits rejected**: Configure GPG signing: https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits

## Code Review & Security

**Pre-commit checks**:
- Lint: `yarn lint` (JS/TS), `black . && isort . && flake8 .` (Python)
- Types: `yarn check-ts` (TypeScript)
- Tests: `yarn test:ci-unit`, `yarn test`, `pytest`
- **CodeQL**: Auto-runs on PRs (JS/Python security scan)

**Checklist**: Build passes, tests pass, no lint/type errors, follows patterns, proper commit format, GPG signed

## Commit Message Format

**Required**: `[component] Message (#issuenumber)`

Components: `backend`, `frontend`, `client-python`, `worker`, `docs`, `tools`, `CI`

Example: `[backend] Fix authentication error handling (#1234)`

## Trust These Instructions

These instructions are comprehensive and tested. Only search for additional information if you encounter a specific error not covered here or need details on a feature not mentioned.

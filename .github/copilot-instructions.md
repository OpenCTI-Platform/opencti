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
yarn install                    # Install Node dependencies (~5 min first time)
yarn install:python             # Install Python deps: pip3 install -r src/python/requirements.txt
yarn build:prod                 # Production build with type checking (~3 min)
# OR for development:
yarn build:dev                  # Dev build with schema generation (~2 min)
```

**Linting & Type Checking**:
```bash
yarn check-ts                   # TypeScript type checking (~30s)
yarn lint                       # ESLint with timing (~45s)
```

**Testing** (requires Docker dependencies):
```bash
yarn test:ci-unit              # Unit tests only, no Docker needed (~2 min)
yarn test:ci-integration-sync  # Integration tests (~10-15 min, needs Docker backend)
yarn test:ci-rules-and-others  # Rules and TAXII tests (~8 min, needs Docker)
```

**Common Issues**:
- **Missing Python deps**: Always run `yarn install:python` after `yarn install`
- **Build timeout**: Use `NODE_OPTIONS=--max_old_space_size=8192` for large builds
- **Schema errors**: Run `yarn build:schema` to regenerate GraphQL schema
- **"Cannot find module opencti-manifest.json"**: Run `yarn get-connectors-manifest` to generate the manifest file (automatically run by `yarn build:prod` and `yarn build:dev`)

### Frontend (opencti-front)

**Install & Build**:
```bash
cd opencti-platform/opencti-front
cp ../.yarnrc.yml .yarnrc.yml
yarn install                    # Install dependencies (~4 min)
yarn relay                      # Generate Relay artifacts (~1 min)
yarn build                      # Production build (~5 min)
```

**Linting & Type Checking**:
```bash
yarn check-ts                   # TypeScript checking (~40s)
yarn lint                       # ESLint (~30s)
```

**Testing**:
```bash
yarn test                       # Unit tests with Vitest (~2 min)
yarn test:coverage              # With coverage (~3 min)
yarn test:e2e                   # End-to-end Playwright tests (~10 min, needs full stack)
```

**Translation Validation** (runs in CI):
```bash
node script/verify-translation.js  # Validates i18n files
```

### Client Python (pycti)

**Setup & Test**:
```bash
cd client-python
pip3 install -r requirements.txt
pip3 install -r test-requirements.txt
pip3 install -e .[dev,doc]     # Editable install with dev dependencies

# Linting (pre-commit hooks use these):
flake8 .                        # Ignore E,W (enforced in CI)
black .                         # Code formatting
isort .                         # Import sorting

# Testing (requires running OpenCTI instance):
python3 -m pytest --cov=pycti --no-header -vv
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
1. **Docker Build** (`ci-docker-build.yml`): Builds platform & worker images (~10 min)
2. **API Tests** (`ci-test-api.yml`): Integration, rules, and unit tests in parallel (~20 min total)
   - Downloads Docker artifacts, spins up backend services (Elasticsearch, Redis, RabbitMQ, MinIO)
   - Runs 3 test jobs: integration-sync, rules-and-others, api-unit-tests
3. **Frontend Tests** (`ci-test-frontend.yml`): Unit tests (~5 min), E2E tests (~15 min), translation validation
4. **Client Python Tests** (`ci-test-client-python.yml`): Matrix tests for Python 3.9-3.12 (~10 min each)
5. **License Check** (`ci-license-check.yml`): Verifies allowed licenses (~5 min)

**Signed Commits Required**: All commits MUST be GPG signed (`check-verified-commit.yml` enforces this).

## Local Development Setup

**Prerequisites**:
```bash
# Enable corepack for Yarn 4.12.0:
corepack enable                 # REQUIRED: Downloads correct Yarn version

# Install Docker/Podman:
sudo sysctl -w vm.max_map_count=262144  # Required for Elasticsearch

# Ensure Node.js ≥20, Python 3.9-3.12 are installed
```

**Start Infrastructure**:
```bash
cd opencti-platform/opencti-dev
docker compose up -d
# Services: Elasticsearch (9200), Redis (6379), RabbitMQ (5672), MinIO (9000), Kibana (5601)
```

**Run Backend**:
```bash
cd opencti-platform/opencti-graphql
cp config/default.json config/development.json  # Edit admin password & token
cp ../.yarnrc.yml .yarnrc.yml
yarn install && yarn install:python
yarn start                      # API on http://localhost:4000
```

**Run Frontend** (separate terminal):
```bash
cd opencti-platform/opencti-front
cp ../.yarnrc.yml .yarnrc.yml
yarn install
yarn start                      # Frontend on http://localhost:3000
```

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

- **ESLint**: `eslint.config.mjs` (v9 flat config) in both graphql & front
- **TypeScript**: `tsconfig.json` in each TS project, strict mode enabled
- **Vitest**: Multiple configs for different test suites (ci-unit, ci-integration, dev)
- **Python**: `.flake8`, `.isort.cfg`, `pyproject.toml` (black, mypy configs)

## Common Pitfalls & Solutions

1. **Yarn command fails**: Missing `.yarnrc.yml` - ALWAYS copy it first
2. **"Module not found" errors**: Run `yarn install:python` for backend, check Relay artifacts for frontend
3. **Test failures in CI**: Local tests pass but CI fails → Check Docker service health, increase timeouts
4. **Build out of memory**: Add `NODE_OPTIONS=--max_old_space_size=8192` before yarn commands
5. **ElasticSearch won't start**: Run `sudo sysctl -w vm.max_map_count=262144`
6. **Unsigned commits rejected**: Configure GPG signing: https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits

## Commit Message Format

**Required**: `[component] Message (#issuenumber)`

Components: `backend`, `frontend`, `client-python`, `worker`, `docs`, `tools`, `CI`

Example: `[backend] Fix authentication error handling (#1234)`

## Trust These Instructions

These instructions are comprehensive and tested. Only search for additional information if you encounter a specific error not covered here or need details on a feature not mentioned.

# OpenCTI Development Instructions for Copilot

## Repository Overview

OpenCTI is an open-source cyber threat intelligence platform for managing, structuring, and visualizing technical and non-technical threat intelligence. It uses a knowledge schema based on STIX2 standards with a GraphQL API backend and React frontend.

**Repository Size**: ~278MB  
**Primary Languages**: TypeScript/JavaScript (~3,650 files), Python (~174 files)  
**Node Version**: >= 20.0.0 (tested with Node 22)  
**Python Version**: 3.9, 3.10, 3.11, 3.12 (3.11 recommended)  
**Package Manager**: Yarn 4.12.0 (via Corepack)

## Project Structure

```
opencti/
├── .github/               # CI/CD workflows and GitHub configurations
│   └── workflows/         # GitHub Actions (ci-main.yml, ci-test-*.yml)
├── client-python/         # Python client library (pycti)
├── docs/                  # MkDocs documentation
├── opencti-platform/      # Main platform code
│   ├── .yarnrc.yml       # Yarn configuration (IMPORTANT: copy to subprojects)
│   ├── opencti-front/    # React frontend with GraphQL client
│   └── opencti-graphql/  # Node.js GraphQL API backend
├── opencti-worker/        # Python background worker
└── scripts/ci/           # CI helper scripts and docker-compose
```

## Critical Build Requirements

### ⚠️ ALWAYS Follow This Sequence

**For Frontend (opencti-front):**
```bash
cd opencti-platform/opencti-front
npm install -g corepack  # REQUIRED: Enables Yarn 4
corepack enable
cp ../yarnrc.yml .       # CRITICAL: Copy Yarn config from parent
yarn install            # Install dependencies
yarn relay              # Generate GraphQL queries
yarn build              # Build for production
```

**For Backend (opencti-graphql):**
```bash
cd opencti-platform/opencti-graphql
npm install -g corepack  # REQUIRED: Enables Yarn 4
corepack enable
cp ../yarnrc.yml .       # CRITICAL: Copy Yarn config from parent
yarn install            # Install JS dependencies
yarn install:python     # Install Python dependencies (pip3 install -r src/python/requirements.txt)
yarn build              # Alias for: yarn install:python && yarn build:prod
```

**For Python Client (client-python):**
```bash
cd client-python
pip3 install -r requirements.txt
pip3 install -e .[dev,doc]  # Install in development mode with extras
pytest                       # Run tests (requires OpenCTI API running)
```

### Build Commands Quick Reference

| Component | Install | Build | Lint | Test |
|-----------|---------|-------|------|------|
| Frontend | `yarn install` | `yarn build` | `yarn lint` | `yarn test` |
| Backend | `yarn install && yarn install:python` | `yarn build:prod` | `yarn lint` | `yarn test:ci-unit` |
| Python Client | `pip install -r requirements.txt && pip install -e .` | `python3 -m build` | `flake8` | `pytest` |

## Testing

### Frontend Tests
```bash
cd opencti-platform/opencti-front
yarn test              # Unit tests with Vitest
yarn test:coverage     # With coverage
yarn test:e2e          # Playwright E2E tests (requires running backend)
yarn check-ts          # TypeScript type checking
```

### Backend Tests
```bash
cd opencti-platform/opencti-graphql
yarn check-ts                    # TypeScript type checking
yarn test:dev                    # Integration tests (requires full stack)
yarn test:ci-unit               # Unit tests only (no dependencies)
yarn test:ci-integration        # Integration tests
yarn test:ci-rules-and-others   # Rules and TAXII tests
```

**IMPORTANT**: Backend integration tests require running infrastructure (Redis, Elasticsearch, RabbitMQ, Minio). Use Docker Compose from `scripts/ci/docker-compose.yml` for local testing.

### Python Client Tests
```bash
cd client-python
pytest ./tests/01-unit/          # Unit tests
pytest ./tests/02-integration/   # Integration tests (requires API)
cd examples && bash run_all.sh   # Example scripts
```

## Linting

### Pre-commit Hooks
The repository uses `.pre-commit-config.yaml` with:
- **isort** and **black** for Python
- **eslint** for JavaScript/TypeScript
- **YAML/JSON validators**

```bash
# Install pre-commit hooks
pre-commit install
# Run manually on all files
pre-commit run --all-files
```

### Manual Linting
```bash
# Frontend
cd opencti-platform/opencti-front && yarn lint

# Backend  
cd opencti-platform/opencti-graphql && yarn lint

# Python
cd client-python && flake8
```

## CI/CD Pipeline

**Main Workflow**: `.github/workflows/ci-main.yml`

The CI runs 5 parallel jobs on every push/PR:
1. **Build Image** - Builds Docker images for platform and worker
2. **API Tests** - Integration tests, rules tests, unit tests (requires Docker images)
3. **Frontend Tests** - Unit tests, E2E tests, translation verification
4. **Python Client Tests** - Tests against Python 3.9-3.12
5. **License Check** - Verifies all dependencies have approved licenses

**Test Execution Time**: 
- Backend integration tests: ~10-15 minutes
- Frontend E2E tests: ~15-20 minutes
- Full CI pipeline: ~30-45 minutes

## Common Issues and Workarounds

### 1. Yarn Config Not Found
**Error**: `Unable to find @yarnpkg/plugin-constraints`  
**Fix**: ALWAYS copy `.yarnrc.yml` from `opencti-platform/` to the working directory:
```bash
cp opencti-platform/.yarnrc.yml opencti-platform/opencti-front/
cp opencti-platform/.yarnrc.yml opencti-platform/opencti-graphql/
```

### 2. Python EXTERNALLY-MANAGED Error
**Error**: `error: externally-managed-environment`  
**Fix**: Remove the marker file (already done in Dockerfile):
```bash
rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED
```

### 3. Node Memory Issues
**Error**: `JavaScript heap out of memory`  
**Fix**: Increase Node memory limit:
```bash
NODE_OPTIONS=--max_old_space_size=8192 yarn test
NODE_OPTIONS=--max_old_space_size=8192 yarn build
```

### 4. Missing Python Dependencies
**Error**: Import errors for Python modules  
**Fix**: Backend requires Python dependencies installed via:
```bash
cd opencti-platform/opencti-graphql
yarn install:python  # Or: pip3 install -r src/python/requirements.txt
```

### 5. Docker Network Issues in CI
When running tests locally with Docker, create the network first:
```bash
docker network create runner-docker-network
```

### 6. Integration Tests Require Backend Services
Backend tests need Redis, Elasticsearch, RabbitMQ, and Minio running. Use:
```bash
cd scripts/ci
docker compose --profile backend up -d
# Wait for services
./wait-for-url-200.sh http://localhost:9200/_cluster/health 120 2
```

## Commit Message Format

All commits MUST follow this format:
```
[component] Message (#issue-number)
```

**Components**: `backend`, `frontend`, `client-python`, `worker`, `docs`, `tools`, `CI`

**Example**: `[backend] Fix GraphQL schema generation (#1234)`

**All commits must be signed**. Configure GPG signing: https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits

## Key Configuration Files

| File | Purpose | Location |
|------|---------|----------|
| `.yarnrc.yml` | Yarn 4 configuration, security settings | `opencti-platform/` |
| `package.json` | Dependencies and scripts | `opencti-platform/opencti-{front,graphql}/` |
| `tsconfig.json` | TypeScript configuration | `opencti-platform/opencti-{front,graphql}/` |
| `vitest.config.*.ts` | Test configurations | `opencti-platform/opencti-graphql/` |
| `eslint.config.mjs` | ESLint configuration | `opencti-platform/opencti-{front,graphql}/` |
| `.pre-commit-config.yaml` | Pre-commit hooks | Root |
| `requirements.txt` | Python dependencies | `client-python/`, `opencti-worker/src/` |

## Development Workflow

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/opencti.git
   cd opencti
   git remote add upstream https://github.com/OpenCTI-Platform/opencti.git
   ```

2. **Setup Environment**:
   ```bash
   # Install Node dependencies
   cd opencti-platform/opencti-graphql
   npm install -g corepack && corepack enable
   cp ../.yarnrc.yml .
   yarn install && yarn install:python
   
   cd ../opencti-front
   cp ../.yarnrc.yml .
   yarn install
   
   # Install Python client
   cd ../../client-python
   pip3 install -r requirements.txt
   pip3 install -e .[dev,doc]
   
   # Install pre-commit hooks
   pre-commit install
   ```

3. **Make Changes**: Create feature branch, implement changes with tests

4. **Validate Locally**:
   ```bash
   # Type check
   yarn check-ts
   
   # Lint
   yarn lint
   
   # Test
   yarn test  # or yarn test:ci-unit for backend
   ```

5. **License Verification** (CRITICAL before PR):
   ```bash
   # Backend
   cd opencti-platform/opencti-graphql
   yarn verify-licenses
   
   # Frontend
   cd ../opencti-front
   yarn verify-licenses
   ```

6. **Commit with Signed Commit**: Use format `[component] Message (#issue)`

7. **Open PR**: All CI checks must pass including:
   - Build succeeds
   - All tests pass
   - Linting passes
   - License check passes
   - CodeQL security scan passes

## Docker Build

**Production Build**:
```bash
cd opencti-platform
docker build -f Dockerfile -t opencti/platform:latest .
```

**Testing Build**:
```bash
docker build -f Dockerfile --target testing -t opencti/platform:testing .
```

**Worker Build**:
```bash
cd opencti-worker
docker build -f Dockerfile -t opencti/worker:latest .
```

## Important Notes

- **DO NOT** modify dependencies without verifying licenses match the approved list
- **DO NOT** commit `node_modules/`, build artifacts, or Python virtual environments
- **DO** run `yarn relay` in frontend after GraphQL schema changes
- **DO** copy `.yarnrc.yml` when working in front/graphql subdirectories
- **DO** ensure commits are signed with GPG
- **ALWAYS** run linters and type checkers before committing
- **ALWAYS** test your changes against the full CI pipeline locally when possible

## License Verification

Only these licenses are approved for dependencies:
- MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, CC0-1.0
- MPL-2.0, LGPL-3.0 (frontend only), Python-2.0, OFL-1.1
- BlueOak-1.0.0, WTFPL, 0BSD, Unlicense

Use `yarn verify-licenses` to check compliance before adding dependencies.

## Quick Troubleshooting

1. **Build fails with Yarn errors** → Check `.yarnrc.yml` is copied correctly
2. **Python import errors** → Run `yarn install:python` in backend
3. **GraphQL schema errors** → Run `yarn relay` in frontend
4. **Test timeout** → Increase with `NODE_OPTIONS=--max_old_space_size=8192`
5. **Integration tests fail** → Ensure Docker services are running (see scripts/ci/docker-compose.yml)
6. **TypeScript errors** → Run `yarn check-ts` to verify type consistency
7. **Lint errors** → Run `yarn lint` and fix issues or use pre-commit hooks

## Additional Resources

- **Documentation**: https://docs.opencti.io
- **Development Guide**: docs/docs/development/
- **API Reference**: https://docs.opencti.io/latest/reference/api/
- **Community Slack**: https://community.filigran.io

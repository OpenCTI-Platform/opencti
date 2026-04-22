# OpenCTI Project Instructions

> **Deep-dive references** — read the relevant doc before touching the related code:
> - [Backend Architecture (opencti-graphql)](instructions/backend.instructions.md)
> - [Frontend Architecture (opencti-front)](instructions/frontend.instructions.md)
> - [Python Client & Worker](instructions/python.instructions.md)
> - [Documentation Authoring (docs)](instructions/docs.instructions.md)
> - [Code Review Guidelines](instructions/code-review.instructions.md)

> **Copilot Skills** (`.github/skills/`) — procedural playbooks, load the relevant one before starting the task:
> - `create-module` — Scaffold a new backend domain module (entity type, schema, resolvers, converter)
> - `create-migration` — Create a new ElasticSearch database migration file
> - `create-react-component` — Create a new Relay-connected React component
> - `create-creation-form` — Scaffold a creation form drawer (Formik + Relay mutation)
> - `create-playbook-component` — Add a new playbook automation component
> - `create-workflow` — Scaffold a new GitHub Actions workflow

## Project Overview

OpenCTI is a cyber threat intelligence platform built with a **monorepo structure** containing:
- **opencti-platform/opencti-graphql**: Node.js/TypeScript GraphQL API backend
- **opencti-platform/opencti-front**: React/TypeScript frontend with Relay
- **client-python**: Python library (pycti) for API access
- **opencti-worker**: Python worker for background tasks
- **docs**: MkDocs documentation

## Global Commands & Setup

### 1. Enable Corepack (first-time only)
Only needed if Yarn is not already available. Run once per machine:
```bash
corepack enable
```
Do **not** add this before every command — assume a dev environment already has corepack enabled.

### 2. Copy .yarnrc.yml (first install only)
Only needed when running `yarn install` for the first time in a subdirectory that does not already have `.yarnrc.yml`:

```bash
# Example for backend
cd opencti-platform/opencti-graphql
cp ../.yarnrc.yml .yarnrc.yml
yarn install
```

Do **not** copy `.yarnrc.yml` before running tests or other commands — it only matters for `yarn install`.

### 3. Root NX Commands (run from repo root)
The root `package.json` uses **NX** to orchestrate all workspaces at once. Prefer these over manually running commands in each subdirectory:

```bash
# Install all dependencies (frontend + backend + Python)
yarn deps          # without Python virtualenv
yarn deps:venv     # with Python virtualenv (recommended)

# Start all dev servers
yarn dev           # without Python virtualenv
yarn dev:venv      # with Python virtualenv

# Build everything
yarn build         # without Python virtualenv
yarn build:venv    # with Python virtualenv

# Run all tests
yarn test          # without Python virtualenv
yarn test:venv     # with Python virtualenv

# Lint everything
yarn lint

# Regenerate GraphQL schema across all packages
yarn graphql
```

The `:venv` variants wrap the command with a Python virtual environment — use them when working on `client-python` or `opencti-worker` and running the backend app.

### 4. Local Development Stack
Start the necessary infrastructure (Elastic, Redis, RabbitMQ, MinIO):
```bash
cd opencti-platform/opencti-dev
docker compose up -d
```
**(ElasticSearch requires `vm.max_map_count=262144`)**

## Common Pitfalls

- **Yarn install fails**: Is `.yarnrc.yml` present in the subdirectory? Run `cp ../.yarnrc.yml .yarnrc.yml` then retry.
- **Yarn not found**: Run `corepack enable` once.
- **Python Dependencies**: Backend requires `yarn install:python`.
- **Relay**: Frontend requires `yarn relay` after any GraphQL changes.
- **Node Memory**: Use `NODE_OPTIONS=--max_old_space_size=8192` for large builds.

## Safety Rules

### Destructive Git & File Operations
**NEVER** run any operation that could cause loss of uncommitted work without explicit user approval. This includes:
- `git reset --hard`, `git checkout -- <file>`, `git clean -fd`
- `git stash drop`, `git rebase`, `git push --force`
- Deleting or overwriting files that may contain unsaved changes

**Before** running any such command:
1. Run `git status` and `git diff` to identify uncommitted or unstaged changes.
2. Present a **clear, plain-language summary** of exactly what would be lost (e.g. "This will discard your unsaved changes to `src/foo.ts` and `src/bar.ts`").
3. **Wait for explicit approval** before proceeding.

## Commit Message Format

**Required**: `[component] Message (#issuenumber)`

Components: `backend`, `frontend`, `client-python`, `worker`, `docs`, `tools`, `CI`

Example: `[backend] Fix authentication error handling (#1234)`

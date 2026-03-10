# OpenCTI Project Instructions

> **Deep-dive references** — read the relevant doc before touching the related code:
> - [Backend Architecture (opencti-graphql)](instructions/backend.instructions.md)
> - [Frontend Architecture (opencti-front)](instructions/frontend.instructions.md)
> - [Python Client & Worker](instructions/python.instructions.md)
> - [Code Review Guidelines](instructions/code-review.instructions.md)

> **Copilot Skills** (`.github/skills/`) — procedural playbooks:
> - `create-workflow` — Scaffold a new GitHub Action workflow (example)

## Project Overview

OpenCTI is a cyber threat intelligence platform built with a **monorepo structure** containing:
- **opencti-platform/opencti-graphql**: Node.js/TypeScript GraphQL API backend
- **opencti-platform/opencti-front**: React/TypeScript frontend with Relay
- **client-python**: Python library (pycti) for API access
- **opencti-worker**: Python worker for background tasks
- **docs**: MkDocs documentation

## Global Commands & Setup

### 1. Enable Corepack First (CRITICAL)
Before any `yarn` command, enable corepack to use the pinned Yarn version (4.12.0):
```bash
corepack enable
```

### 2. Copy .yarnrc.yml (CRITICAL)
**Before any `yarn` command** in subdirectories, you MUST copy `.yarnrc.yml` from `opencti-platform/`.
Checks will fail without it.

```bash
# Example for backend
cd opencti-platform/opencti-graphql
cp ../.yarnrc.yml .yarnrc.yml
yarn install
```

### 3. Local Development Stack
Start the necessary infrastructure (Elastic, Redis, RabbitMQ, MinIO):
```bash
cd opencti-platform/opencti-dev
docker compose up -d
```
**(ElasticSearch requires `vm.max_map_count=262144`)**

## Common Pitfalls

- **Yarn Failures**: Did you copy `.yarnrc.yml`? Did you run `corepack enable`?
- **Python Dependencies**: Backend requires `yarn install:python`.
- **Relay**: Frontend requires `yarn relay` after any GraphQL changes.
- **Node Memory**: Use `NODE_OPTIONS=--max_old_space_size=8192` for large builds.

## Commit Message Format

**Required**: `[component] Message (#issuenumber)`

Components: `backend`, `frontend`, `client-python`, `worker`, `docs`, `tools`, `CI`

Example: `[backend] Fix authentication error handling (#1234)`

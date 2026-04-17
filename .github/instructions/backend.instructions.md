---
applyTo: "opencti-platform/opencti-graphql/**"
description: "Backend architecture, standards, and implementation patterns for OpenCTI GraphQL API"
---

# Backend (opencti-graphql)

## Scope
The `opencti-graphql` module is the core API server for the OpenCTI platform. It handles:
- GraphQL API requests (Apollo Server)
- Data persistence (ElasticSearch/OpenSearch)
- Message queuing (RabbitMQ)
- File storage (MinIO/S3)
- Cache (Redis)
- Authentication & Authorization

## Architecture

### Tech Stack
- **Runtime**: Node.js ≥ 20
- **Language**: TypeScript
- **API**: GraphQL (Apollo Server)
- **Database**: ElasticSearch or OpenSearch
- **Messaging**: RabbitMQ
- **Object Storage**: MinIO (S3 compatible)
- **Cache**: Redis

### Key Directories
- `src/`: Source code
  - `schema/`: GraphQL schema definitions
  - `resolvers/`: GraphQL resolvers
  - `domain/`: Business logic and service layer
  - `database/`: Database connectors and utilities
  - `migrations/`: Database migration scripts
- `config/`: Configuration files (NODE_ENV based)
- `tests/`: Unit and integration tests

## Setup & Build

### Prerequisites
- **Yarn 4.13.0**: Enabled via `corepack enable`.
- **Python Deps**: Required for some internal logic.

### Commands
> Only copy `.yarnrc.yml` from the parent if running `yarn install` for the first time. It is not needed for tests or builds once dependencies are installed.

```bash
# Installation
yarn install
yarn install:python

# Build
yarn build:prod    # Production build
yarn build:dev     # Dev build (generates schema)
yarn build:schema  # Generate GraphQL schema & types

# Linting & Types
yarn check-ts      # Check TypeScript types
yarn lint          # Run ESLint

# Testing
yarn test:ci-unit              # Fast unit tests
yarn test:ci-integration-sync  # Integration tests
```

## Implementation Patterns

> **Detailed Patterns**:
> - [Module Architecture](backend/patterns/module-architecture.md)
> - [GraphQL Schema & Resolvers](backend/patterns/schema-resolvers.md)
> - [Database & Migrations](backend/patterns/database-migrations.md)
> - [Error Handling](backend/patterns/error-handling.md)
> - [Performance](backend/patterns/performance.md)
> - [Testing](backend/patterns/testing.md)

## Common Issues
- **Missing Python deps**: If you see errors about missing modules, run `yarn install:python`.
- **Heap Memory**: If build fails with OOM, use `NODE_OPTIONS=--max_old_space_size=8192`.
- **Schema mismatch**: If types are out of sync, run `yarn build:schema`.

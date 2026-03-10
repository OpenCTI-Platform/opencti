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
- **Yarn 4.12.0**: Enabled via `corepack enable`.
- **Python Deps**: Required for some internal logic.

### Commands
Before running commands, ensure `.yarnrc.yml` is present (copy from parent).

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

### 1. GraphQL Schema & Resolvers
- Use **Attribute-based Access Control (ABAC)** where possible.
- Ensure all new types have corresponding strict types in TypeScript.
- Run `yarn build:schema` after modifying `.graphql` files to generate types.

### 2. Database & Migrations
- **ElasticSearch/OpenSearch** is the primary data store for STIX data.
- Use `migrate create` (or `yarn migrate:add`) to create schema migrations.
- **Relations**: Handle relations carefully; cleaner relations script exists (`yarn clean:relations`).

### 3. Error Handling
- Use typed errors from the `config/errors.ts` or equivalent.
- Ensure sensitive info is not leaked in error messages.

### 4. Performance
- Use `DataLoader` patterns for resolving relationships to avoid N+1 queries.
- Be mindful of payload sizes; STIX objects can be large.

## Common Issues
- **Missing Python deps**: If you see errors about missing modules, run `yarn install:python`.
- **Heap Memory**: If build fails with OOM, use `NODE_OPTIONS=--max_old_space_size=8192`.
- **Schema mismatch**: If types are out of sync, run `yarn build:schema`.

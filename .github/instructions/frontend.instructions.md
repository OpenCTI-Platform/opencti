---
applyTo: "opencti-platform/opencti-front/**"
description: "Frontend architecture, component structure, and Relay patterns"
---

# Frontend (opencti-front)

## Scope
The `opencti-front` module provides the web-based user interface for the OpenCTI platform.
It uses **Relay** for data fetching and **Material UI** for styling.

## Architecture

### Tech Stack
- **Framework**: React 19
- **Bundler**: Vite
- **Data Fetching**: Relay (GraphQL)
- **UI Library**: Material UI (MUI) v6
- **Routing**: Internal routing
- **Testing**: Vitest, Playwright (E2E)

### Key Directories
- `src/`: Source code
  - `components/`: Reusable strict UI components
  - `private/`: Authenticated application logic & components
  - `public/`: Public pages (login, registration)
  - `utils/`: Helper functions
  - `relay/`: Relay environment configuration
- `packages/`: Monorepo packages (if any)
- `tests_e2e/`: End-to-End tests

### Aliases (tsconfig.json)
- `@common/*`: `src/components/common/*`
- `@components/*`: `src/private/components/*`
- `src/*`: `src/*`

## Setup & Build

### Prerequisites
- **Yarn 4.12.0**: Enabled via `corepack enable`.
- **Relay Compiler**: Essential for GraphQL fragment generation.

### Commands
Before running commands, ensure `.yarnrc.yml` is present (copy from parent).

```bash
# Installation
yarn install

# Development
yarn relay        # 1. Compile Relay artifacts (CRITICAL)
yarn start        # 2. Start dev server (Vite)
# OR: yarn dev    # Short for relay + vite

# Build
yarn build        # Production build
yarn build:standalone # Keep artifacts

# Linting & Types
yarn check-ts     # Check types
yarn lint         # Run ESLint

# Testing
yarn test         # Unit tests (Vitest)
yarn test:e2e     # E2E (Playwright)
```

## Implementation Patterns

> **Detailed Patterns**:
> - [Relay Data Fetching](frontend/patterns/relay-data-fetching.md)
> - [Component Structure](frontend/patterns/component-structure.md)
> - [Forms & Validation](frontend/patterns/forms-validation.md)
> - [Styling](frontend/patterns/styling-mui.md)
> - [Components](frontend/patterns/components.md)

## Common Issues
- **Missing Data**: Did you run `yarn relay`?
- **Type Errors**: Check generated types in `__generated__` folders.
- **Build Failures**: Ensure node_modules/ dependencies are consistent.

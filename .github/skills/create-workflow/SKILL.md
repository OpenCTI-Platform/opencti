---
name: create-workflow
description: "Use when: scaffolding a new GitHub Actions CI/CD workflow, adding automation for tests, builds, releases, or security scans"
---

# Create GitHub Action Workflow

## Prerequisites
- **Workflow Name**: e.g., "Review Security Scans"
- **Trigger**: e.g., `pull_request`, `push`
- **Job Steps**: e.g., checkout, install deps, run scan

## Procedure

### Step 1 — Create Workflow File
Create a new file in `.github/workflows/<workflow-name>.yml`.

```yaml
name: [Workflow Name]

on:
  [Trigger]:
    branches: [master]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 #v7
        with:
          node-version: 20
          cache: 'yarn'
      - run: corepack enable
      - run: yarn install --immutable
      - name: Run Scan
        run: [Command]
```

### Step 2 — Verify Job Dependencies
Ensure any required secrets or environment variables are available.

### Step 3 — Commit
Commit with format: `[CI] Add <workflow-name> workflow (#<issue-number>)`

---
name: create-migration
description: "Use when: creating a new ElasticSearch database migration file, adding or transforming data at deploy time"
---

# Create Database Migration

## Prerequisites
- **Description**: Short snake_case description of the change (e.g., `add_description_to_user`).

## Procedure

### Step 1 — Generate Migration File
Use the current timestamp (ms) as prefix.
File: `opencti-platform/opencti-graphql/src/migrations/<timestamp>-<description>.ts`.

### Step 2 — Implement Migration Pattern
Use the standard template with logging and execution context.

```typescript
import { logMigration } from '../config/conf';

const message = '[MIGRATION] <Description>';

export const up = async (next: any) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);

  // Implementation here
  // usage: const context = executionContext('migration');
  //        await someDomainFunction(context, SYSTEM_USER, args);

  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
   };

export const down = async (next: any) => {
  next();
};
```

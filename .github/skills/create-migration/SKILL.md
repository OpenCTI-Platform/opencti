# Create Database Migration

## Prerequisites
- **Description**: Short snake_case description of the change (e.g., `add_description_to_user`).

## Procedure

### Step 1 — Generate Migration File
Use the current timestamp (ms) as prefix.
File: `opencti-platform/opencti-graphql/src/migrations/<timestamp>-<description>.js`.

### Step 2 — Implement Migration Pattern
Use the standard template with logging and execution context.

```javascript
import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';

const message = '[MIGRATION] <Description>';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  
  // Implementation here
  // usage: await someDomainFunction(context, SYSTEM_USER, args);
  
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
```

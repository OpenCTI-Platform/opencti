# Database & Migrations

- **ElasticSearch/OpenSearch** is the primary data store for STIX data.
- **Rules**:
  - Migrations must be **idempotent**.
  - Use `executionContext('migration')` and `SYSTEM_USER`.
  - Always call `next()` at the end.
  - Always add a  logMigration.info into loops to have the visibility on number of items processed.
  - For update or delete query, make sure to use dedicated functions for migration : `elUpdateByQueryForMigration`, `elDeleteByQueryForMigration`
  - The timestamp prefix must always be greater than the last migration file.
- **Command**: Use `yarn migrate:add` (wraps `migrate create`) to generate files.
- **Relations**: Handle relations carefully; cleaner relations script exists (`yarn clean:relations`).

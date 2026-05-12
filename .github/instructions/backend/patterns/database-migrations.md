# Database & Migrations

- **ElasticSearch/OpenSearch** is the primary data store for STIX data.
- **Rules**:
  - Migrations must be **idempotent**.
  - Use `executionContext('migration')` and `SYSTEM_USER`.
  - Always call `next()` at the end.
- **Command**: Use `yarn migrate:add` (wraps `migrate create`) to generate files.
- **Relations**: Handle relations carefully; cleaner relations script exists (`yarn clean:relations`).

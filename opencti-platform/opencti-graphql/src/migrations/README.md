# Best practices on migration writing

## Use yarn command to create new migration file

This will create a new JS migration file under folder migrations  with a “latest” timestamp prefix.
```bash
cd opencti-platform/opencti-graphql
yarn migrate:add <migration-name>
```

The migration process is a blocking process on startup, so it is important:
- that the migration does the minimum necessary work
- that the status is explicit on the logs (number of items processed / number of item expected, etc.)

## Other resources

- [Agent instructions](../../../../.github/instructions/backend/patterns/database-migrations.md)
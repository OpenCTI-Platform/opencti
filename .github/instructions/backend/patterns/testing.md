# Testing

- **Framework**: Vitest.
- **Context**: Import `testContext`, `ADMIN_USER` from `tests/utils/testQuery`.
- **Integration**: Prefer integration tests that run against the local stack or injected data.
- **Always use the yarn scripts** — never call `vitest` or `vitest --config ...` directly:
  ```bash
  yarn test:ci-unit              # Fast unit tests
  yarn test:ci-integration-sync  # Integration tests (sync)
  yarn test:ci-integration       # Integration tests
  yarn test:ci-rules-and-others  # Rules and other tests
  yarn test:dev                  # Dev mode (full run)
  ```

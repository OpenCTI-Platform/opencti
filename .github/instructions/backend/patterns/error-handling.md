# Error Handling

- Use typed errors from `src/config/errors.js` (factory functions, not classes — e.g. `AuthenticationFailure`, `ForbiddenAccess`).
- **Security**: Ensure sensitive info (paths, internal IDs) is not leaked in error messages.

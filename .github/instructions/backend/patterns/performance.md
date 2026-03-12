# Performance

- Use `DataLoader` patterns for resolving relationships to avoid N+1 queries.
- Be mindful of payload sizes; STIX objects can be large.
- **Caching**: Use Redis managers for frequently accessed configuration or user data.

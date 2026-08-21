# Performance

- Use `DataLoader` patterns for resolving relationships to avoid N+1 queries.
- Be mindful of payload sizes; STIX objects can be large.
- **Caching**: Use Redis managers for frequently accessed configuration or user data.
- **Event Loop**: For loops iterating over large arrays, call `await doYield()` from `src/utils/eventloop-utils.ts` on each iteration. It yields the event loop back to Node.js every 50 ms, preventing the server from blocking other requests during CPU-intensive work. Prefer the ready-made helpers in `src/utils/data-processing.ts` (`asyncFilter`, `asyncMap`, `uniqAsyncMap`) which call `doYield()` internally.

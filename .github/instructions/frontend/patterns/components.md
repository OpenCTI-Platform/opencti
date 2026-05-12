# Components

- Prefer functional components with hooks.
- Do **not** wrap list row (`*Line`) components in `React.memo` — this is not the pattern used. `React.memo` is reserved for specialized graph/visualization nodes.
- Keep components focused and small.

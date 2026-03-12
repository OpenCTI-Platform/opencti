# Data Fetching (Relay)

- Use **Fragment Colocation**: Define data requirements alongside components.
- **Naming Convention**: `ComponentName_propName`.
- **Usage**: Always use `useFragment` (or `usePreloadedQuery` for roots).
- **Store Updates**: Mutations must use `updater` functions (e.g., `insertNode` from `utils/store`) to update the Relay store immediately without refetching.
- Always run `yarn relay` after modifying GraphQL.

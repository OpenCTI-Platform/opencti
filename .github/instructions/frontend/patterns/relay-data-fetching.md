# Data Fetching (Relay)

- Use **Fragment Colocation**: Define data requirements alongside components.
- **Naming Convention**: `ComponentName_propName`.
- **Usage**: Use `useFragment` for fragment components. For query roots, use `usePreloadedQuery`, `useLazyLoadQuery`, or the custom `usePreloadedPaginationFragment` hook (`src/utils/hooks/usePreloadedPaginationFragment.ts`) for paginated lists.
- **Store Updates**: Mutations must use `updater` functions (e.g., `insertNode` from `utils/store`) to update the Relay store immediately without refetching.
- Always run `yarn relay` after modifying GraphQL.

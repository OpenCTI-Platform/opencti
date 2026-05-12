# Component Structure

- **Location**: `src/private/components`.
- **Hierarchy Pattern**: `Root` -> `List` -> `Line` | `Card`.
- **Modern pattern**: List + Line fragments are now **co-located in a single file** and rendered via the `<DataTable>` component. Separate `*Lines.tsx`/`*Line.tsx` file pairs are the legacy pattern — do not create new ones.
- **Fragments**: Each level composes the fragments of its children.

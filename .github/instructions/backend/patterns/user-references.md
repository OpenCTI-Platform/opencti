# User References and the User Merge

An administrator can merge two user accounts (`src/modules/userMerge/`, documented in
`docs/docs/administration/users-merge.md`). The merge re-points the references held by the
source account to the target account, and then deletes the source.

The merge only rewrites what its register knows about. A user reference that is missing from
the register stays on the source account. That account is disabled during the merge and deleted
afterwards. Nothing fails: whatever relied on the reference stops working for the target.

## When this applies

This applies to any change that **stores a user id**. That includes ids stored in a JSON payload,
in a stored filter, in a manifest, or in a default value.

Before you go further, ask what happens if that user is merged into another one:

| What the stored id gives the user | Example | Disposition |
|---|---|---|
| Ownership, an assignment, a subscription | an assignee, the owner of a trigger, a notification recipient | `transfer` |
| Access | authorized members, a list of exempted users | `transfer` or `conditional` |
| An identity to run as | the user of a connector, a feed or an ingestion | `transfer` or `conditional` |
| Attribution of something past | who did what in an audit trail | may stay: `retain` |

When the stored id gives the user something, the target must inherit it.

## Checklist

### 1. A typed attribute — enforced by CI
An attribute declared with `type: 'string'`, `format: 'id'` and `entityTypes: [ENTITY_TYPE_USER]` is
found by the schema discovery. This also covers an attribute nested in a `standard` or `nested`
object.

`userMerge-schemaDiscovery-test.ts` fails until the attribute has a rule in
`userMerge-scalarRules.ts` and a row in `userMerge-register.ts`.

### 2. A stored filter — enforced by CI
A stored filter is an attribute whose name ends with `filters`. It names users by value
(`creator_id`, `objectAssignee`…).

The same test fails until the filter is listed in `USER_MERGE_FILTER_TARGETS`
(`userMerge-filterTargets.ts`) with a register row.

### 3. A JSON, Base64 or untyped payload — NOT enforced, your responsibility
Nothing detects an id held inside a serialized payload: a manifest, a definition, a configuration,
or a `default_values` list. To declare it:
- add a row to `USER_MERGE_REGISTER` (`userMerge-register.ts`) with its disposition;
- for `transfer` or `conditional`, add a target to `USER_MERGE_BLOB_TARGETS`
  (`userMerge-blobTargets.ts`), or claim the row in the handler that owns the field;
- if the platform serves the entity from its cache, add its type to
  `USER_MERGE_CACHED_ENTITY_TYPES` (`userMerge-engine.ts`).

### 4. Every `transfer` and `conditional` row needs a handler — enforced by CI
`userMerge-registeredCoverage-test.ts` fails when a row of either disposition is claimed by no
handler. Such a row would block the deletion of every merged source account.

Do not declare a reference as `retain` just to make a test pass. `retain` means the merge is
right to leave the reference on the source.

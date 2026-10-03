# Data sanity manager

The goal of the data sanity manager is to run periodic or on-demand operations to improve data consistency.

## GraphQL API

There is no graphical interface yet, but here is some graphQL queries that can be used.

### Estimate impacted data

Run a dry run to know how many elements an operation modifies, **without changing any data**. Use it before requesting an actual run.

```graphql
query DataSanityOperationDryRun($operation_name: String!) {
  dataSanityOperationDryRun(operation_name: $operation_name) {
    estimated_impact {
      key
      count
    }
  }
}
```

Variables:

```json
{
  "operation_name": "caseSensitiveDuplicatedId"
}
```

### Stop an execution that is stale

If there is some issue with an operation, and a restart has been done on the platform. After a while the operation will be detected as stale and restarted. If there is a need to avoid this restart the operation can be stopped.
After that the operation can be started again using `dataSanityOperationRequestRun` on demand.

```graphql
mutation DataSanityOperationStop($operation_name: String!) {
  dataSanityOperationStop(operation_name: $operation_name)
}
```

Variables:

```json
{
  "operation_name": "caseSensitiveDuplicatedId"
}
```

### Request to run an operation

Schedule an operation for the next manager cycle. Use it to trigger a `run_once` operation that already ran, or to relaunch an operation you stopped.

```graphql
mutation DataSanityOperationRequestRun($operation_name: String!) {
  dataSanityOperationRequestRun(operation_name: $operation_name)
}
```

Variables:

```json
{
  "operation_name": "caseSensitiveDuplicatedId"
}
```

## Operations

### caseSensitiveDuplicatedId

The `standard_id` resolver used to be case-sensitive, so entities whose only difference was letter
casing (for example the attack patterns `Phishing` and `phishing`) received two distinct identifiers
and coexisted as duplicates. Now that the resolver ignores case, those entities collide on the same
`standard_id`.

This operation recomputes the `standard_id` of every Attack Pattern and Course of Action, groups the
entities that now collide, and merges each group into a single entity.

!!! note

    A group that fails to merge is logged and skipped: one faulty group never aborts the whole run.
    Run [Estimate impacted data](#estimate-impacted-data) first to know how many groups are concerned.
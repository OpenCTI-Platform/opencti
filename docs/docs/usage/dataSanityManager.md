# Data sanity manager

The goal of the data sanity manager is to run periodic or on-demand operations to improve data consistency.

## Schedule and configuration

The [data sanity manager](../deployment/advanced/managers.md#data-sanity-manager) runs every 10 minutes by default. At each cycle, it runs the operations that never ran, and the operations requested with [`dataSanityOperationRequestRun`](#request-to-run-an-operation). An operation that already ran does not run again until it is requested.

| Parameter                                  | Environment variable                          | Default value         | Description                                                                 |
|:-------------------------------------------|:----------------------------------------------|:----------------------|:----------------------------------------------------------------------------|
| data_sanity_manager:enabled                | DATA_SANITY_MANAGER__ENABLED                  | `true`                | Enable/disable the data sanity manager                                      |
| data_sanity_manager:interval               | DATA_SANITY_MANAGER__INTERVAL                 | 600000                | Interval between two cycles of the manager (in ms)                          |
| data_sanity_manager:stale_running_threshold | DATA_SANITY_MANAGER__STALE_RUNNING_THRESHOLD | 86400000 (24 hours)   | Time after which a running operation is considered stale (in ms)            |

## GraphQL API

There is no graphical interface yet: use the GraphQL queries below. Run them on the `/graphql` endpoint of the platform, for example from the [GraphQL playground](../development/api-usage.md) at `https://[your-opencti-instance]/public/graphql`. Every query and mutation requires the `Bypass all capabilities` capability (see [Users and Role Based Access Control](../administration/users.md#list-of-capabilities)).

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

If the platform restarts while an operation is running, the operation stays marked as running. After 24 hours, the manager considers it stale and runs it again at its next cycle. To change this delay, set `data_sanity_manager:stale_running_threshold` (see [Schedule and configuration](#schedule-and-configuration)). To avoid this new run, stop the operation.
After that, you can start the operation again on demand with `dataSanityOperationRequestRun`.

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
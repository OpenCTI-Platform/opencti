# User Merge Operational Runbook

This document defines the operational procedure for executing user account merges on an OpenCTI platform. It is intended for platform administrators operating under maintenance conditions.

---

## Table of Contents

1. [Overview & Guiding Principles](#1-overview--guiding-principles)
2. [GraphQL API Reference & Parameter Specification](#2-graphql-api-reference--parameter-specification)
   * [2.1 Mutations](#21-mutations)
     * [`userMerge`](#mutation-usermerge)
     * [`userMergeDeleteSource`](#mutation-usermergedeletesource)
   * [2.2 Queries](#22-queries)
     * [`userMergeCoverage`](#query-usermergecoverage)
     * [`userMergeJournal`](#query-usermergejournal)
     * [`userMergeSourceDeletionReadiness`](#query-usermergesourcedeletionreadiness)
   * [2.3 Input Options & Enumerations](#23-input-options--enumerations)
3. [Mandatory Preconditions](#3-mandatory-preconditions)
4. [Per-User Merge Procedure](#4-per-user-merge-procedure)
5. [Source Account Deletion Procedure](#5-source-account-deletion-procedure)
6. [Incident Response & Recovery Guide](#6-incident-response--recovery-guide)
7. [Closing the Batch & Restoring Traffic](#7-closing-the-batch--restoring-traffic)
8. [GraphQL Operations Cheatsheet](#8-graphql-operations-cheatsheet)

---

## 1. Overview & Guiding Principles

The **User Merge** capability reassigns data ownership, entity associations, collaborative links, and audit history from a **source user** onto a **target user**.

### Guiding Principles

* **Manual, Unitary Execution (1-by-1)**: Merges are performed one pair at a time through GraphQL mutations. Batching is controlled externally by the operator (e.g. iterating over a CSV list), allowing human inspection of dry-run reports before each write.
* **Two-Pass Execution**: Every merge runs an in-memory computation (`dryRun: true`) producing a full report before any write occurs. In a real pass (`dryRun: false`), the engine verifies that the platform state has not drifted before committing any update.
* **Platform at Rest**: The merge engine relies on the platform being at rest. Ingestions, connectors, and background workers must be stopped to avoid state divergence during execution.
* **Non-Destructive Merge, Gated Deletion**: The merge operation itself **disables** the source account (`account_status: Expired`) and closes its access. Deleting the source account is a separate, explicitly gated operation requiring full coverage and zero pending references.
* **Strict Idempotency**: All merge handlers are strictly idempotent. If an execution is interrupted, re-running the merge on the same pair is a safe no-op on already applied data.

---

## 2. GraphQL API Reference & Parameter Specification

All queries and mutations require the `BYPASS` capability and the `MERGE_USERS` feature flag:
* `@auth(for: [BYPASS])`
* `@ff(flags: ["MERGE_USERS"])`

---

### 2.1 Mutations

#### Mutation `userMerge`

Executes or previews the merge of a source user into a target user.

```graphql
mutation userMerge(
  $sourceId: ID!
  $targetId: ID!
  $options: UserMergeOptions
): UserMergeResult!
```

##### Arguments

| Argument | Type | Required | Default | Description |
| :--- | :--- | :---: | :---: | :--- |
| `sourceId` | `ID!` | **Yes** | — | The internal ID or standard ID of the user account to merge away. |
| `targetId` | `ID!` | **Yes** | — | The internal ID or standard ID of the user account receiving data and ownership. |
| `options` | `UserMergeOptions` | No | `{ dryRun: true, rightsStrategy: STRICT, acknowledgeExposureChange: false }` | Execution flags controlling dry-run mode, RBAC rights strategy, and safety acknowledgments. |

##### Return Type: `UserMergeResult`

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `ID!` | Unique execution identifier (UUID) assigned to this merge run. |
| `source_id` | `ID!` | Resolved internal ID of the source user. |
| `target_id` | `ID!` | Resolved internal ID of the target user. |
| `dry_run` | `Boolean!` | `true` if this was a simulation run; `false` if writes were committed. |
| `rights_strategy` | `UserMergeRightsStrategy!` | The strategy applied (`STRICT` or `UNION`). |
| `status` | `UserMergeStatus!` | Outcome status: `RUNNING`, `SUCCESS`, or `FAILED`. |
| `started_at` | `DateTime!` | Timestamp when the merge run initiated. |
| `completed_at` | `DateTime` | Timestamp when the merge run terminated. |
| `message` | `String` | Error or diagnostic message if the execution failed or was blocked. |
| `report` | `UserMergeExecutionReport` | Detailed breakdown of changes per handler, alerts, and register coverage. |

##### Sub-structure: `UserMergeExecutionReport`
* `merge_id`: ID of the merge execution.
* `register_version`: Active register version (e.g. `"v5"`).
* `total_updated`: Count of documents written (always `0` during a dry-run).
* `handlers`: Array of `UserMergeHandlerOutcome`:
  * `handler`: Identifier of the handler (e.g. `scalar-user-references`, `filter-user-references`).
  * `updated`: Number of documents updated by this specific handler.
  * `changes`: Array of planned changes:
    * `register_row_id`: Register row answered for.
    * `entity_type`: Target entity type.
    * `count`: Number of entities or documents impacted.
    * `exact`: `true` if the count is strictly exact, `false` if estimated.
    * `detail`: Human-readable explanation of the change.
  * `alerts`: Array of `UserMergeRightsAlert`:
    * `register_row_id`: Register row raising the alert.
    * `kind`: Alert category (`rights`, `exposure`, `activity`).
    * `message`: Detailed explanation of the alert.
    * `blocking`: `true` if this alert aborts the real pass unless `acknowledgeExposureChange: true` is provided.

---

#### Mutation `userMergeDeleteSource`

Permanently deletes the source user account document from the platform after a successful merge.

```graphql
mutation userMergeDeleteSource(
  $sourceId: ID!
  $targetId: ID!
): ID!
```

##### Arguments

| Argument | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `sourceId` | `ID!` | **Yes** | The internal ID of the merged-away source user account to delete. |
| `targetId` | `ID!` | **Yes** | The internal ID of the target user that received the source's data. |

##### Return Type
* Returns `ID!` (the ID of the deleted source user account).

##### Safety Behavior
1. **Re-checks Readiness**: Internally calls `userMergeSourceDeletionReadiness`. If `allowed` is `false`, throws a `FunctionalError` and aborts.
2. **Cascades Suppressed**: Does **not** use `userDelete`, preventing accidental cascading deletions of Triggers, Dashboards, and Public Feeds that now belong to the target user.
3. **Session Purge & Audit**: Kills residual Redis sessions and publishes an audit log event (`deletes merged user <email>`).

---

### 2.2 Queries

#### Query `userMergeCoverage`

Inspects the current completeness of the merge engine against the 99-row user reference register.

```graphql
query userMergeCoverage($disposition: UserMergeDisposition): UserMergeCoverage!
```

##### Arguments

| Argument | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `disposition` | `UserMergeDisposition` | No | Optional filter to view only rows with a specific disposition (`TRANSFER`, `INVALIDATE`, `CONDITIONAL`, `RETAIN`, `OUT_OF_SCOPE`). If omitted, returns all 99 rows. |

##### Return Type: `UserMergeCoverage`

| Field | Type | Description |
| :--- | :--- | :--- |
| `register_version` | `String!` | Register version constant (e.g. `"v5"`). |
| `total` | `Int!` | Total number of rows in the register (99). |
| `covered_count` | `Int!` | Number of rows claimed by registered handlers. |
| `uncovered_count` | `Int!` | Total number of unclaimed rows (includes non-gating retained rows). |
| `gating_uncovered_count` | `Int!` | Number of unclaimed rows that gate source deletion (`TRANSFER` and `CONDITIONAL`). Must be `0` to allow source deletion. |
| `is_complete` | `Boolean!` | `true` when `gating_uncovered_count === 0`. |
| `rows` | `[UserMergeCoverageRow!]!` | Detailed inventory of register rows (`row_id`, `label`, `path`, `disposition`, `covered`, `handler`). |

---

#### Query `userMergeJournal`

Retrieves execution logs recorded by handlers during merge runs.

```graphql
query userMergeJournal(
  $mergeId: ID
  $first: Int
): [UserMergeJournalEntry!]!
```

##### Arguments

| Argument | Type | Required | Default | Description |
| :--- | :--- | :---: | :---: | :--- |
| `mergeId` | `ID` | No | `null` | Target merge execution ID. If omitted, returns recent entries across all merge runs. |
| `first` | `Int` | No | `20` | Maximum number of entries to return (minimum: 1, maximum: 200). |

##### Return Type: `[UserMergeJournalEntry!]!`
* Array of log entries containing `id`, `merge_id`, `source_id`, `target_id`, `handler`, `dry_run`, `status`, `started_at`, `completed_at`, `message`.

---

#### Query `userMergeSourceDeletionReadiness`

Evaluates whether a source user account can be safely deleted.

```graphql
query userMergeSourceDeletionReadiness(
  $sourceId: ID!
  $targetId: ID!
): UserMergeSourceDeletionReadiness!
```

##### Arguments

| Argument | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `sourceId` | `ID!` | **Yes** | The internal ID of the source user account. |
| `targetId` | `ID!` | **Yes** | The internal ID of the target user account. |

##### Return Type: `UserMergeSourceDeletionReadiness`

| Field | Type | Description |
| :--- | :--- | :--- |
| `allowed` | `Boolean!` | `true` if and only if all three deletion preconditions are satisfied. |
| `coverage_complete` | `Boolean!` | `true` if all gating register rows are claimed by handlers. |
| `pending_change_count` | `Int!` | Number of references to the source user that a live dry-run plans to move. Must be `0`. |
| `blockers` | `[String!]!` | Array of human-readable explanations explaining why deletion is refused. Empty when `allowed` is `true`. |

---

### 2.3 Input Options & Enumerations

#### Input `UserMergeOptions`

```graphql
input UserMergeOptions {
  dryRun: Boolean = true
  rightsStrategy: UserMergeRightsStrategy = STRICT
  acknowledgeExposureChange: Boolean = false
}
```

* `dryRun` (`Boolean`, default: `true`):
  * `true`: Executes a simulation pass in memory. Calculates all planned changes and alerts without writing to Elasticsearch or Redis. `total_updated` in the report will be `0`.
  * `false`: Executes the real merge. Recomputes and verifies the plan against current platform state, then commits all updates across platform indices, Redis, and internal caches.
* `rightsStrategy` (`UserMergeRightsStrategy`, default: `STRICT`):
  * `STRICT`: The target user's RBAC rights (groups, roles, capabilities, markings) remain strictly unchanged. Source memberships and permissions are discarded.
  * `UNION`: The target user inherits the source user's group memberships, organization affiliations, and capabilities.
* `acknowledgeExposureChange` (`Boolean`, default: `false`):
  * Must be explicitly passed as `true` in a real pass (`dryRun: false`) if the dry-run reported a blocking alert (`blocking: true`).
  * Triggers include: widening of public sharing endpoints (Feeds, TAXII collections) caused by new markings gained under `UNION`, or service account attribute changes.

#### Enum `UserMergeRightsStrategy`
* `STRICT`: Target permissions are kept intact; source permissions are dropped.
* `UNION`: Target permissions are expanded by unioning source groups and organizations.

#### Enum `UserMergeStatus`
* `RUNNING`: Merge pass is currently executing.
* `SUCCESS`: Merge pass completed with zero fatal errors.
* `FAILED`: Merge pass aborted due to pre-condition failure, unacknowledged alert, or database error.

#### Enum `UserMergeDisposition`
* `TRANSFER`: Reference must be re-pointed to the target user.
* `INVALIDATE`: Reference/access must be revoked, closed, or dropped.
* `CONDITIONAL`: Dependent on lifecycle status or rights strategy.
* `RETAIN`: Reference must remain untouched (historical record or own account identity).
* `OUT_OF_SCOPE`: Not managed by user merge.

---

## 3. Mandatory Preconditions

Before initiating a merge batch, verify and fulfill every requirement in this checklist.

### 3.1 Platform at Rest (Workers & Connectors Stopped)

The platform must experience zero concurrent writes during the merge window.

1. **Stop all ingestion connectors**: Stop all connector containers/processes feeding data into the platform.
2. **Drain and stop background workers**: Ensure Celery/RabbitMQ queues are empty and stop the OpenCTI workers:
   ```bash
   docker compose stop worker connector-*
   ```
3. **Terminate active user sessions**: Notify active users and verify no active sessions remain on the platform.

### 3.2 Feature Flag Enablement

Ensure the `MERGE_USERS` feature flag is enabled in the platform configuration:

```bash
APP__ENABLED_DEV_FEATURES='["MERGE_USERS"]'
```

Verify that the GraphQL schema exposes the `userMerge` mutation and queries.

### 3.3 Operator Account Safeguards

* **Capability Requirement**: The operator executing the GraphQL requests must hold the `BYPASS` capability (Platform Administrator).
* **Identity Guard**: **The operator account must NOT be one of the source accounts being merged.** An operator cannot merge themselves away without terminating their own session mid-batch.

### 3.4 Mandatory Snapshot & Backup

> [!CAUTION]
> **OpenCTI does not have an automated rollback mechanism.**
> Merges write partial documents across live Elasticsearch indices. A snapshot is your only recovery path in the event of an unrecoverable operational mistake.

Create a restorable snapshot of:
1. **Elasticsearch / OpenSearch cluster indices** (all indices, including `.internal_objects`, `.history`, `.deleted_objects`).
2. **Redis key-value store**.

Verify that the snapshot completed successfully before launching the first merge.

### 3.5 Reverse Proxy & Network Timeout Settings

Merges on accounts holding large volumes of history or entities can take between 10 and 45 seconds.

* Check the **reverse proxy read timeout** (Nginx, AWS ALB, Cloudflare). Default proxy timeouts are often set to 60 seconds. If an account has extensive history, set the proxy timeout to at least **120 seconds** (`proxy_read_timeout 120s;`).
* Confirm `app:request_timeout` in OpenCTI config (default: 20 minutes) is not constrained.

---

## 4. Per-User Merge Procedure

For each account pair `(sourceId, targetId)`, execute the following 4-step loop.

### 4.1 Step 1: Execute Dry-Run

Run the `userMerge` mutation with `dryRun: true`:

```graphql
mutation UserMergeDryRun($sourceId: ID!, $targetId: ID!) {
  userMerge(
    sourceId: $sourceId
    targetId: $targetId
    options: {
      dryRun: true
      rightsStrategy: STRICT
      acknowledgeExposureChange: false
    }
  ) {
    id
    status
    source_id
    target_id
    rights_strategy
    report {
      total_updated
      handlers {
        handler
        changes {
          register_row_id
          entity_type
          count
          exact
          detail
        }
        alerts {
          register_row_id
          kind
          message
          blocking
        }
      }
    }
  }
}
```

### 4.2 Step 2: Review and Interpret the Report

Inspect the returned `report.handlers`:

1. **Verify Handlers & Counts**:
   * `source-account-disable`: Count should be `1` (or `0` if source was already expired).
   * `scalar-user-references`: Documents where the source was `creator_id`, `user_id`, etc.
   * `filter-user-references`: Number of saved filters, triggers, or feeds containing the source user UUID.
   * `blob-user-references`: Dashboards, playbooks, and draft update patches rewritten.
   * `history-attribution` & `history-context-data-payload`: Past events and audit logs being re-attributed.
   * `stix-operational-relations`: Assignee/Participant links being re-pointed or deduplicated.
2. **Inspect RBAC Differences & Rights Strategy**:
   * **STRICT (Default & Recommended)**: The target user retains strictly their own groups, roles, and markings. Source memberships are dropped.
   * **UNION**: Source groups, organizations, and capabilities are added to the target. Use only when the target must inherit existing source clearances.
3. **Inspect Alerts (`blocking: true` vs `blocking: false`)**:
   * **Public Sharing Exposure Alerts**: If the source owned a public feed or taxii collection, or if `UNION` grants new markings widening public sharing, an alert is raised. If `blocking: true`, you must pass `acknowledgeExposureChange: true` during Step 3.
   * **Restricted Members Alert**: If the source has restricted members on objects but the target lacks authorization management rights, a blocking alert is raised.
   * **Textual Mentions / Corrupt Filters**: Informational alerts indicating that an unparsable filter or a free-text search UUID was found and left untouched.

### 4.3 Step 3: Execute Real Merge

Execute the merge with `dryRun: false`. If a public exposure alert was flagged in Step 2, set `acknowledgeExposureChange: true`:

```graphql
mutation UserMergeApply($sourceId: ID!, $targetId: ID!) {
  userMerge(
    sourceId: $sourceId
    targetId: $targetId
    options: {
      dryRun: false
      rightsStrategy: STRICT
      acknowledgeExposureChange: true
    }
  ) {
    id
    status
    completed_at
    report {
      total_updated
    }
  }
}
```

### 4.4 Step 4: Verify Completion via the Journal

Verify the outcome recorded in the journal:

```graphql
query UserMergeJournalCheck($mergeId: ID!) {
  userMergeJournal(mergeId: $mergeId, first: 20) {
    id
    handler
    status
    updated_count
    message
    started_at
    completed_at
  }
}
```

Confirm that all handlers completed with status `SUCCESS`. The source account is now `Expired`, its API tokens revoked, sessions terminated, and its data references transferred to the target.

---

## 5. Source Account Deletion Procedure

Deleting the source account is an irreversible operation and must **only** be executed after the merge has succeeded and all references have been cleared.

### 5.1 Check Deletion Readiness

Query the deletion gate before attempting deletion:

```graphql
query UserMergeCheckReadiness($sourceId: ID!, $targetId: ID!) {
  userMergeSourceDeletionReadiness(sourceId: $sourceId, targetId: $targetId) {
    allowed
    coverage_complete
    pending_change_count
    blockers
  }
}
```

#### Gate Criteria

The deletion gate enforces three mandatory conditions:
1. `coverage_complete === true`: All 99 register rows are covered by handlers.
2. `pending_change_count === 0`: A live dry-run confirms that zero references still point to the source user.
3. `merged_into === <targetId>`: The source carries the mark a real merge into **this** target wrote on it.

If `allowed` is `false`, review `blockers`. Re-run the merge if references are still pending.

> [!CAUTION]
> **Never delete a merged source account through Settings → Users.**
>
> The merge disables the source, it does not delete it, so the account remains listed with its
> ordinary delete button. That button runs four cascades — triggers and digests, workspaces,
> notifications, public dashboard sharing — which all select by a reference to the account being
> deleted. After a complete merge they find nothing. If the merge missed a reference, they **delete**
> the trigger or the dashboard that carries it, and those objects now belong to the target. A gap a
> re-run would repair becomes a permanent loss.
>
> The platform refuses that button on any account carrying `merged_into`. Do not work around the
> refusal by clearing the field unless you have run the readiness query first and it answered
> `allowed: true` (see 5.3).

### 5.2 Execute Permanent Deletion

Once `allowed: true`, permanently delete the source account:

```graphql
mutation UserMergeDeleteSource($sourceId: ID!, $targetId: ID!) {
  userMergeDeleteSource(sourceId: $sourceId, targetId: $targetId)
}
```

The mutation re-verifies readiness internally before deletion, deletes the User entity document, kills residual sessions, and emits an administrative audit log (`deletes merged user <email>`). It does not run the cascades, and it does not go through the ordinary deletion path, so the `merged_into` mark never has to be cleared.

### 5.3 If the deletion mutation is not available

Some platform versions ship the readiness query without `userMergeDeleteSource`. The source account then has to be removed through Settings → Users, and the mark has to be cleared first — which means the check the mutation would have done internally becomes the operator's responsibility.

1. Run the readiness query of 5.1. **Stop here unless it answers `allowed: true`.**
2. Clear the mark on the source account:

```graphql
mutation ClearMergeMark($id: ID!) {
  userEdit(id: $id) {
    fieldPatch(input: [{ key: "merged_into", value: null }]) { id }
  }
}
```

3. Delete the account through Settings → Users.

Between steps 2 and 3 the account is deletable by anyone with the rights, and the cascades will run on it. Keep that window as short as possible, and do not perform this sequence while workers or connectors are running.

---

## 6. Incident Response & Recovery Guide

### 6.1 Incident 1: HTTP 504 / Client Disconnection / Timeout

> [!IMPORTANT]
> **DO NOT RE-LAUNCH THE MERGE IMMEDIATELY.**
> Neither Node.js nor Apollo cancels an in-flight mutation when a client disconnects. The merge is continuing server-side.

**Procedure**:
1. Retrieve the latest journal entries without specifying a `mergeId`:
   ```graphql
   query {
     userMergeJournal(first: 10) {
       merge_id
       handler
       status
       updated_count
       started_at
     }
   }
   ```
2. Identify the active `merge_id` for your pair.
3. Poll `userMergeJournal(mergeId: "<merge_id>")` until the last handler (`source-runtime-invalidation`) has completed.
4. If all handlers succeeded, the merge is complete. Do not re-run.

### 6.2 Incident 2: Node Crash or Restart Mid-Merge

If the backend server process crashed or was restarted while a merge was writing:

1. **Safety Assessment**: The merge engine uses atomic updates and bulk writes with conflict detection. Handlers are strictly idempotent.
2. **Procedure**:
   - Inspect `userMergeJournal` to find the last handler that completed.
   - Re-run the merge with the exact same parameters (`dryRun: false`).
   - The handlers that previously wrote will cleanly find 0 documents left to update (`updated: 0`), and the remaining handlers will complete.

### 6.3 Incident 3: Platform Divergence Error

**Error Message**: `Platform state changed between the dry pass and the real pass, nothing was written`

* **Root Cause**: The engine recomputes all handler plans immediately before the first write. If any document count or plan fingerprint diverges from the dry pass, the engine refuses to write to prevent inconsistent state.
* **Typical Triggers**: Ingestion workers were left running and modified entities; an active user logged in and created references.
* **Resolution**:
  1. Verify workers and connectors are stopped.
  2. Run a fresh dry-run (`dryRun: true`).
  3. Inspect the updated report and proceed with the real run.

### 6.4 Incident 4: Unacknowledged Blocking Alerts

**Error Message**: `Merge blocked by unacknowledged alerts, nothing was written`

* **Root Cause**: A handler detected a security posture change (e.g. public feed exposure change under `UNION`).
* **Resolution**: Review the dry-run alerts. If the security change is intended, pass `acknowledgeExposureChange: true` in `options`.

---

## 7. Closing the Batch & Restoring Traffic

Once all accounts in the batch have been processed:

1. **Post-Merge Verification Checks**:
   - Log in as the target user.
   - Verify that the source user's dashboards, investigation workspaces, cases, and incidents are visible and editable.
   - Check the Activity Log to confirm audit traces (`merges user <source> into user <target>`).
2. **Restart Services**:
   ```bash
   docker compose start worker connector-*
   ```
3. **Re-open Platform Traffic**: Re-enable user access through the reverse proxy.

---

## 8. GraphQL Operations Cheatsheet

### Check Register Coverage
```graphql
query CheckCoverage {
  userMergeCoverage {
    total
    covered_count
    uncovered_count
    gating_uncovered_count
    is_complete
  }
}
```

### Full Merge Flow
```graphql
# 1. Dry Run
mutation DryRun($src: ID!, $dst: ID!) {
  userMerge(sourceId: $src, targetId: $dst, options: { dryRun: true, rightsStrategy: STRICT }) {
    id
    status
    report { total_updated }
  }
}

# 2. Real Run
mutation ApplyMerge($src: ID!, $dst: ID!) {
  userMerge(sourceId: $src, targetId: $dst, options: { dryRun: false, rightsStrategy: STRICT, acknowledgeExposureChange: true }) {
    id
    status
    report { total_updated }
  }
}

# 3. Check Deletion Readiness
query CheckReadiness($src: ID!, $dst: ID!) {
  userMergeSourceDeletionReadiness(sourceId: $src, targetId: $dst) {
    allowed
    blockers
    pending_change_count
  }
}

# 4. Delete Source User
mutation DeleteSource($src: ID!, $dst: ID!) {
  userMergeDeleteSource(sourceId: $src, targetId: $dst)
}
```

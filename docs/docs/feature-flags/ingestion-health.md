# Ingestion health: unreleased parts

!!! warning "Unreleased feature"

    This page documents the parts of [ingestion health](../administration/ingestion-health.md) still under development. They are only available when the `INGESTION_HEALTH` feature flag is enabled (`APP__ENABLED_DEV_FEATURES`), and this page is not published.

    When they are released: merge each section below into `administration/ingestion-health.md` at the place given, move `assets/ingestion-health-parameters.png` to `administration/assets/`, and delete this page.

## Last run failed check

To add to the **Health checks** table of the published page, after **Feed or sync source denied access**:

| Check | Applies to | Kind | Severity | Fails when | What to do |
|---|---|---|---|---|---|
| Last run failed | Connectors, except stream connectors | Runtime | Advisory | The last run of the connector ended with an error | Read the error of the last work of the connector |

To add to **How the checks work (details)**, after **Feed and synchronization executions**:

**Connector runs**

- **Last run failed** judges the last work of the connector, once processed: it fails when the connector itself closed the work with an error. The errors of the workers on single elements of the work do not make a failed run.
- A work that ended more than 5 minutes before the last run of the connector belongs to an earlier run: it is not judged. The check waits for the work of the last run.
- A stream connector has no run: the check does not apply to it.
- The check is advisory: the connector may still ingest, and its next successful run clears it.

When released, also restore in the published page:

- in the definition of a runtime check: "its heartbeat, its last execution, its errors";
- in the **Evaluation** details: "For errors reported by a connector (on ping, or as the error of a work)".

## Platform parameters

To add as the first subsection of **Configure ingestion health**, before the manager configuration (renamed **Platform configuration**).

Also restore in **Evaluation** details: "A disabled check is not evaluated, on any ingestion (see [Configure ingestion health](#configure-ingestion-health))."

### Platform parameters

Go to **Settings > Parameters**, section **Ingestion health monitoring**. You need the **Manage parameters** capability (`SETTINGS_SETPARAMETERS`).

| Parameter | Description | Default |
|---|---|---|
| Notification delay (in minutes) | Time a health status must stay unchanged before it is notified. Only configurable with the [Enterprise Edition](../administration/enterprise.md). See [Notifications](../administration/ingestion-health.md#notifications). | 5 |
| Health checks | Every check, with its kind (runtime or configuration). Turn a check off to stop evaluating it on every ingestion. | All on |

![Ingestion health parameters](assets/ingestion-health-parameters.png)

!!! tip "Turn off a check rather than ignore it"

    If a check does not fit your platform (for instance, you knowingly run ingestions with regular users), turn it off: the ingestions it degrades go back to their real status, and their notifications stop.

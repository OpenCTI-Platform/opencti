# Dissemination assurance

Sharing an indicator with a security platform does not prove that the platform uses it. Dissemination assurance
closes the loop: the stream connectors report where each indicator is actually deployed, the platforms report the
hits they observe, and OpenAEV can prove with benign tests that a deployed indicator is detected or prevented.

Dissemination assurance is available in every edition and uses no AI: every status and counter is computed
deterministically from what the connectors and OpenAEV report.

## Deployments

When a stream connector pushes an indicator to a security platform, it reports the result to OpenCTI. Each report
creates or updates a `deployed-on` relationship from the indicator to the security platform. The relationship
carries the lifecycle of the indicator on that platform:

| Attribute            | Description                                                                 |
|:---------------------|:----------------------------------------------------------------------------|
| Deployment status    | `pending`, `deployed`, `active`, `failed`, `removed` or `expired`.          |
| External id          | The identifier of the indicator in the security platform.                  |
| Deployed at          | When the platform first accepted the indicator.                             |
| Last synchronization | When the connector last reported on the indicator.                          |
| Removed at           | When the platform confirmed the removal.                                    |
| Hit count            | The number of hits the platform reported for the indicator.                 |
| First hit            | When the earliest hit the platform reported happened.                      |
| Last hit             | When the platform last reported a hit.                                      |
| Validation status    | `not_requested`, `requested`, `detected`, `prevented`, `missed` or `error`. |
| Last validation      | When the last validation result was received.                               |
| Deployment error     | The error the platform returned, when the deployment failed.                |

Reports are idempotent: a connector can report the same state again without creating a new relationship. A
`deployed` report never downgrades an `active` deployment, and a `pending` report never downgrades a live
(`deployed` or `active`) one. Reports are applied in the order they arrive, so a `failed` or `removed` report always
takes effect. Only the platform manager sets the `expired` status.

Hits reported by a security platform are also recorded as a sighting of the indicator by the platform, so they show
up with the other sightings of the indicator. The deployment is the reference record of the hits: the sighting is
rebuilt from its hit count, first hit and last hit on every report, so a sighting left behind by an interrupted
report, or deleted by mistake, is repaired by the next report of the platform without counting any hit twice.

### Supported connectors

The following stream connectors report deployments, and hits when the security platform exposes its detections
(see the README of each connector):

- Microsoft Sentinel Intel
- Microsoft Defender Intel
- CrowdStrike Endpoint Security
- Splunk
- Elastic Security Intel
- Google SecOps SIEM
- SentinelOne Intel
- Palo Alto Cortex XDR Intel
- Zscaler
- Cloudflare Rules List

### Indicator counters

Each indicator carries derived counters, refreshed automatically from its deployments. They can be used in
filters, lists and dashboards:

| Counter                    | Description                                                     |
|:---------------------------|:----------------------------------------------------------------|
| Deployments count          | The number of platforms where a stream connector recorded the indicator, whatever the status: the evidence that the indicator was disseminated. |
| Deployment platforms count | The number of platforms where the indicator is deployed or active. |
| Deployment failed count    | The number of platforms where the deployment failed.            |
| Expired deployments count  | The number of platforms where the deployment was flagged expired because its removal was never confirmed. |
| Validated platforms count  | The number of platforms where a validation proved a detection or a prevention. |
| Hit platforms count        | The number of platforms that reported at least one hit.         |

The counters are kept up to date from the deployment events. Deleting or merging a security platform removes its
deployments without individual events, so the platform manager then recomputes the counters of every indicator
with deployments; it also rechecks them continuously in bounded batches.

## Viewing deployments

- On an indicator, the **Deployments** tab lists the security platforms the indicator is deployed on, with the
  status, hits and validation of each deployment.
- On a security platform, the **Deployments** tab lists the indicators deployed on the platform, with the same
  information and the assurance metrics of the platform.

From both tabs, an analyst with the *Update knowledge* capability can:

- **Retry deployment**: available on a failed, removed or expired deployment. The connector deploys the indicator
  again.
- **Remove from this platform**: withdraws the indicator from this platform only. The connector removes it and
  reports it as removed. If the removal is not confirmed within the grace period, the deployment is flagged as
  expired.

## Dissemination assurance pages

Go to **Defense > Dissemination assurance**.

- **Overview** shows the funnel from created to disseminated, deployed, validated and hit indicators, the
  deployment and validation statuses, and the indicators that expired but are still deployed. The period can be
  changed. An indicator counts as disseminated once a stream connector recorded it on a security platform, whatever
  the outcome (pending, deployed, failed, removed or expired): the detection flag of an indicator is not evidence of
  dissemination.
- **Lists** gives ready-made lists of the indicators that need attention: disseminated but not deployed (recorded
  by a connector but live on no platform), deployed but never validated, and expired but still deployed (revoked or
  past their validity while still live on a platform, or flagged expired because their removal was never confirmed).
- **Validation requests** lists the IOC validation requests sent to OpenAEV and their results.

## Validating deployments with OpenAEV

An IOC validation request asks OpenAEV to prove that deployed indicators are detected or prevented by the
security platforms. Use the **Request validation** button on the deployments of an indicator or a platform: the
request covers the live deployments, up to 200 indicators, never validated first (deployments without proof, or
whose last validation missed or failed, then the proven ones). Deployments already waiting for the results of
another request are left out. Choose the benign test kinds, then send the request. It is delivered to OpenAEV by
the IOC validation connector. A deployment that starts waiting for another request in the meantime is skipped, and
listed with the reason in the new request.

OpenAEV never runs anything without an explicit approval by one of its operators, and only runs the benign test
kinds allowed in its settings. By default, the validation never contacts adversary infrastructure: DNS resolution
does not connect to the resolved address, network tests can be sent to a sinkhole, and HTTP tests require an
egress proxy. See the [OpenAEV documentation](https://docs.openaev.io/latest/usage/build/scenario/ioc-validation/)
for the approval workflow and the safety settings.

When OpenAEV sends the results, the validation status of each deployment is updated to `detected`, `prevented`,
`missed` or `error`, and the request shows the outcome of every indicator and platform pair.

## Dashboard template

To build a dashboard of the dissemination assurance metrics, go to **Dashboards > Custom dashboards**, click
**Create from template** and choose **Dissemination assurance**. The dashboard shows the deployments by status,
the validations by outcome, the live deployments and missed validations by security platform, the latest failed
deployments, and the indicators that are deployed but never validated, disseminated but not deployed, or expired
but still deployed (revoked while live, or flagged expired). It is a regular custom dashboard: its widgets can be
edited, moved and shared.

## Notifications

Create live triggers in **Notifications** to be told when a deployment needs attention:

| Event                       | Entity type     | Filters                                                        |
|:----------------------------|:----------------|:---------------------------------------------------------------|
| Deployment failed           | Deployed on     | Deployment status = `failed`                                   |
| Validation missed           | Deployed on     | Validation status = `missed`                                   |
| Removal never confirmed     | Deployed on     | Deployment status = `expired`                                  |
| Expired but still deployed  | Indicator       | Revoked = `true` and Deployment platforms count greater than 0 |

The **Removal never confirmed** trigger fires when the platform manager flags a deployment as expired, once the
removal grace period has passed without confirmation from the connector.

## Configuration

The platform manager that flags expired deployments and keeps the counters up to date can be configured with the
following parameters:

| Parameter                                           | Environment variable                                 | Default value | Description                                                     |
|:----------------------------------------------------|:-----------------------------------------------------|:--------------|:----------------------------------------------------------------|
| indicator_deployment_manager:enabled                | INDICATOR_DEPLOYMENT_MANAGER__ENABLED                | true          | Enable the indicator deployment manager.                        |
| indicator_deployment_manager:interval               | INDICATOR_DEPLOYMENT_MANAGER__INTERVAL               | 60000         | Interval between two runs of the manager, in milliseconds.      |
| indicator_deployment_manager:removal_grace_period   | INDICATOR_DEPLOYMENT_MANAGER__REMOVAL_GRACE_PERIOD   | 86400000      | Time given to a connector to confirm a removal, in milliseconds. |
| indicator_deployment_manager:reconciliation_max_pages | INDICATOR_DEPLOYMENT_MANAGER__RECONCILIATION_MAX_PAGES | 1000        | Pages of 1,000 indicators whose counters are recomputed right after a security platform is deleted or merged. |
| indicator_deployment:report_rate_limit              | INDICATOR_DEPLOYMENT__REPORT_RATE_LIMIT              | 200           | Maximum deployment reports per second.                          |
| indicator_deployment:batch_rate_limit               | INDICATOR_DEPLOYMENT__BATCH_RATE_LIMIT               | 20            | Maximum batch deployment reports per second.                    |
| indicator_deployment:hits_rate_limit                | INDICATOR_DEPLOYMENT__HITS_RATE_LIMIT                | 200           | Maximum hit reports per second.                                 |
| ioc_validation:timeout_days                         | IOC_VALIDATION__TIMEOUT_DAYS                         | 7             | Days after which an unanswered IOC validation request times out. |

## API

Connectors use the following GraphQL mutations, also available in the Python client (`pycti`):

- `indicatorReportDeployment`: reports the deployment status of one indicator on one platform.
- `indicatorReportDeployments`: reports the deployment status of a batch of indicators on one platform.
- `indicatorReportHits`: reports the hits of one indicator on one platform.

These mutations require both the "Update knowledge" and the "Connectors API usage" (`CONNECTORAPI`) capabilities, as
granted by the default *Connector* role: the account of a stream connector or of any other integration writing the
deployments back (for example a SIEM add-on) must have that role, or a role with both capabilities.

The deployment state (deployment status, external id, deployed at, last synchronization, removed at, hit count, first
hit, last hit, deployment error) is written the same way everywhere else. Creating, importing or editing a `deployed-on`
relationship with these values set is reserved to connector accounts (bundle imports, platform synchronization) and
administrators. Any other account can still create a `deployed-on` relationship, which then starts in its default
state (`pending`, no hit, validation not requested), but cannot set or reset the state of an existing one, including
through a creation that updates an existing relationship. The analyst actions of the Deployments tabs (retry, remove)
stay available with the "Update knowledge" capability.

A security platform able to prove a validation test from its own data (for example a SIEM that searched for the
benign test of a request) reports the outcome with `iocValidationReportResults(id, platformId, results)`: each result
gives an indicator, `detected`, `prevented` or `missed`, and optionally the observation date, a hit count and the
evidence. Only the pairs of the request on that platform still waiting for an answer are updated, so a result already
received from OpenAEV is never overwritten. Each result is recorded as a sighting of the indicator by the platform,
negative for a miss.

A validation result is proof attributed to the platform, so it is accepted only from the connector account that
recorded the deployments of the pairs on that platform (the integration reporting its deployment statuses), from the
OpenAEV connector the request was sent to, or from an administrator. Any other account, even with the "Update
knowledge" capability, is refused, including an account that only edited or re-created a deployment (for example to
add a description): editing a relationship lists you among its creators, but does not make you speak for the
platform. The same rule protects every other way to write the validation fields of a deployment
(validation status, last validation, validation run): editing the relationship, or creating it again with these
fields so that the existing relationship is updated, requires one of these accounts, resets to "not requested"
included, and creating or importing a deployment that already carries a validation outcome is reserved to an OpenAEV
IOC validation connector or an administrator.

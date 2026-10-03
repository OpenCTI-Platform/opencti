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
| Last hit             | When the platform last reported a hit.                                      |
| Validation status    | `not_requested`, `requested`, `detected`, `prevented`, `missed` or `error`. |
| Last validation      | When the last validation result was received.                               |
| Deployment error     | The error the platform returned, when the deployment failed.                |

Reports are idempotent: a connector can report the same state again without creating a new relationship, and an
active deployment is never downgraded by a late report. Only the platform manager sets the `expired` status.

Hits reported by a security platform are also recorded as a sighting of the indicator by the platform, so they show
up with the other sightings of the indicator.

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
| Deployment platforms count | The number of platforms where the indicator is deployed or active. |
| Deployment failed count    | The number of platforms where the deployment failed.            |
| Validated platforms count  | The number of platforms where a validation proved a detection or a prevention. |
| Hit platforms count        | The number of platforms that reported at least one hit.         |

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
  changed.
- **Lists** gives ready-made lists of the indicators that need attention: disseminated but not deployed, deployed
  but never validated, and expired but still deployed.
- **Validation requests** lists the IOC validation requests sent to OpenAEV and their results.

## Validating deployments with OpenAEV

An IOC validation request asks OpenAEV to prove that deployed indicators are detected or prevented by the
security platforms. Use the **Request validation** button on the deployments of an indicator or a platform: the
request covers the live deployments, never validated first. Choose the benign test kinds, then send the request.
It is delivered to OpenAEV by the IOC validation connector. A deployment already waiting for the results of another
request is skipped, and listed with the reason in the new request.

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
deployments, and the indicators that are deployed but never validated, disseminated but not deployed, or revoked
but still deployed. It is a regular custom dashboard: its widgets can be edited, moved and shared.

## Notifications

Create live triggers in **Notifications** to be told when a deployment needs attention:

| Event                       | Entity type     | Filters                                                        |
|:----------------------------|:----------------|:---------------------------------------------------------------|
| Deployment failed           | Deployed on     | Deployment status = `failed`                                   |
| Validation missed           | Deployed on     | Validation status = `missed`                                   |
| Expired but still deployed  | Indicator       | Revoked = `true` and Deployment platforms count greater than 0 |

## Configuration

The platform manager that flags expired deployments and keeps the counters up to date can be configured with the
following parameters:

| Parameter                                           | Environment variable                                 | Default value | Description                                                     |
|:----------------------------------------------------|:-----------------------------------------------------|:--------------|:----------------------------------------------------------------|
| indicator_deployment_manager:enabled                | INDICATOR_DEPLOYMENT_MANAGER__ENABLED                | true          | Enable the indicator deployment manager.                        |
| indicator_deployment_manager:interval               | INDICATOR_DEPLOYMENT_MANAGER__INTERVAL               | 60000         | Interval between two runs of the manager, in milliseconds.      |
| indicator_deployment_manager:removal_grace_period   | INDICATOR_DEPLOYMENT_MANAGER__REMOVAL_GRACE_PERIOD   | 86400000      | Time given to a connector to confirm a removal, in milliseconds. |
| indicator_deployment:report_rate_limit              | INDICATOR_DEPLOYMENT__REPORT_RATE_LIMIT              | 200           | Maximum deployment reports per second.                          |
| indicator_deployment:batch_rate_limit               | INDICATOR_DEPLOYMENT__BATCH_RATE_LIMIT               | 20            | Maximum batch deployment reports per second.                    |
| indicator_deployment:hits_rate_limit                | INDICATOR_DEPLOYMENT__HITS_RATE_LIMIT                | 200           | Maximum hit reports per second.                                 |
| ioc_validation:timeout_days                         | IOC_VALIDATION__TIMEOUT_DAYS                         | 7             | Days after which an unanswered IOC validation request times out. |

## API

Connectors use the following GraphQL mutations, also available in the Python client (`pycti`):

- `indicatorReportDeployment`: reports the deployment status of one indicator on one platform.
- `indicatorReportDeployments`: reports the deployment status of a batch of indicators on one platform.
- `indicatorReportHits`: reports the hits of one indicator on one platform.

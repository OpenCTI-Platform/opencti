# Hunt connectors

Hunt connectors execute hunts. They are connectors of type `INTERNAL_HUNT`, each one serving one platform, and are deployed like any other connector (see [Connectors](../deployment/connectors.md)). The hunt connectors maintained by Filigran are available in the [connectors repository](https://github.com/OpenCTI-Platform/connectors/tree/master/internal-hunt).

| Platform slug | Platform | Languages |
|---|---|---|
| `splunk` | Splunk | SPL |
| `microsoft-sentinel` | Microsoft Sentinel | KQL |
| `elastic-security` | Elastic Security | ES\|QL, EQL, Lucene |
| `crowdstrike-logscale` | CrowdStrike Falcon LogScale | LogScale query language |
| `google-secops` | Google SecOps | UDM search, YARA-L |
| `opensearch` | OpenSearch (OCSF data) | PPL, Lucene |
| `internet` | Infrastructure tracking on the Internet | Infrastructure queries |

## Registration

At startup a hunt connector registers its platform, the languages it executes and the **security platform** it executes against. The security platform is an Identity of type Security Platform (SIEM, EDR, XDR, SOAR, NDR, ISPM); it is created when missing. Hunts are scoped on security platforms, and the sightings produced by the runs are sighted on them.

Several connectors can serve the same platform type for different security platforms, for instance one Splunk connector per Splunk deployment. The `internet` platform has no security platform.

Registered hunt connectors, their platform and their health are displayed in **Defense > Hunts** when creating a hunt, and in the connectors list.

## Run lifecycle

1. OpenCTI pushes a run to the queue of the connector serving the security platform. The message carries the hunt (hypothesis, Sigma rule, native query for the platform, techniques, targets, indicators, markings), the time window and the limits (maximum results, timeout, evidence caps). A work tracks the run in the connector works.
2. The connector reports the run as `running`, translates the Sigma rule into the platform language (or takes the native query as is), and executes it over the time window.
3. When results are found, the connector sends a STIX bundle: sightings of the techniques and indicators of the hunt, where sighted on the security platform, and observed data referencing the observables extracted from the results, limited to the expected observable types of the hunt. The identifiers are deterministic, so that re-runs update the knowledge instead of duplicating it.
4. The connector reports the run as `completed` with the hits count, the translated query and the evidence sample, as `timeout` when the execution exceeded the run deadline, or as `failed` with the error. Failed and timed out runs are retried with the same backoff and never create knowledge.

For a query test, the connector translates the logic and reports the translated query without executing it.

OpenCTI only accepts the report of a run from the connector it was dispatched to, never accepts a second report of a terminated run, and caps the evidence it stores. Raw values are never sent: each evidence value is hashed, only a truncated preview is kept.

## Developing a hunt connector

The Python library `pycti` provides the helpers of the hunt connector contract:

- `ConnectorType.INTERNAL_HUNT`, the connector type,
- `helper.register_hunt_platform(platform, languages, security_platform_name, security_platform_type, supports_preview, max_concurrent_runs)`, the registration,
- `helper.listen_hunt(callback)`, the consumption of the runs (the callback receives the run message),
- `helper.report_hunt_run(run_id, status, ...)`, the run report,
- `api.hunt` and `api.hunt_run`, the hunt and hunt run entities.

The connectors SDK provides an `InternalHuntConnector` base class and a template implementing the full lifecycle (deadline, Sigma translation through pySigma, result mapping to STIX, evidence hashing): a new platform only implements the query execution.

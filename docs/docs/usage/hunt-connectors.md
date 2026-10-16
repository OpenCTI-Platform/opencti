# Hunt connectors

Hunt connectors execute hunts. They are connectors of type `INTERNAL_HUNT`, each one serving one platform, and are deployed like any other connector (see [Connectors](../deployment/connectors.md)). The hunt connectors maintained by Filigran are available in the [connectors repository](https://github.com/OpenCTI-Platform/connectors/tree/master/internal-hunt).

| Platform slug | Platform | Languages |
|---|---|---|
| `splunk` | Splunk | SPL |
| `microsoft-sentinel` | Microsoft Sentinel | KQL |
| `microsoft-defender` | Microsoft Defender XDR | KQL |
| `elastic-security` | Elastic Security | ES\|QL, EQL, Lucene |
| `crowdstrike-logscale` | CrowdStrike Falcon LogScale | LogScale query language |
| `google-secops` | Google SecOps | UDM search, YARA-L |
| `opensearch` | OpenSearch (OCSF data) | PPL, Lucene |

## Before you start

Each hunt connector queries its platform with an account of its own. Give that account the least-privilege permissions
below, not an administrator role: the connector only reads, and only creates and deletes its own search jobs.

The same list shows in the product, in **Defense > Hunts**: the setup checklist, above the list until every prerequisite is
met and behind **Hunting setup** afterwards, has a **Required permissions of** panel per deployed hunt connector, filled
by the connector at registration, with a link to the section of this page. When you deploy or update a hunt connector
from the connector catalog, a **Before you start** notice of the form links to the section of that connector.

![Setup checklist of Defense > Hunts: the required permissions of a Splunk hunt connector, with its setup documentation](assets/hunt-connector-permissions.png)

### Splunk

| | |
|---|---|
| Credential | An authentication token of a dedicated service account (user name and password when tokens are disabled). |
| Console | Splunk Web: **Settings > Roles**, **Settings > Users**, **Settings > Tokens**. |
| Network | The REST API (management port, `8089` by default) reachable from the connector. |

Step by step:

1. In **Settings > Roles > New Role**, create `opencti_hunt` without inherited roles: capability `search`, and on the **Indexes** tab the indexes the hunts must cover.
2. Give the role read access to the app of `SPLUNK_HUNT_APP` (`search` by default): **Apps > Manage Apps > Permissions** of the app.
3. In **Settings > Users > New User**, create `svc_opencti_hunt` with the role `opencti_hunt` only.
4. In **Settings > Tokens**, enable token authentication if needed, then **New Token** for `svc_opencti_hunt`, and set it as `SPLUNK_HUNT_TOKEN`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Capability `search` | Create the search jobs of the hunts, read their status and results, cancel and delete them. |
| Read on the app `SPLUNK_HUNT_APP` | The search jobs run in this app namespace (`search` by default). |
| Indexes allowed to search (`srchIndexesAllowed`) | Every index the hunts must cover, for example `wineventlog`, `sysmon`, `main`. |
| Capability `edit_tokens_own` | Optional: lets the account create its own authentication token. |
| Read access to the data models | Only with the `splunk_cim` pipeline and the `data_model` output format (`tstats` searches). |

Jobs run in the `SPLUNK_HUNT_OWNER` / `SPLUNK_HUNT_APP` namespace (`nobody` / `search` by default) and are deleted once their results are read.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
SPLUNK_HUNT_URL=https://splunk.example.com:8089
SPLUNK_HUNT_TOKEN=ChangeMe
SPLUNK_HUNT_APP=search
SPLUNK_HUNT_SEARCH_PREFIX=index=wineventlog OR index=sysmon
```

A hunt run refused by the platform fails as **Access denied on** the platform, with the sentence of the connector naming the missing permission and what to grant.

Full configuration: [connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/internal-hunt/splunk-hunt/README.md).

### Microsoft Sentinel

| | |
|---|---|
| Credential | A Microsoft Entra ID app registration with a client secret, or a managed identity (`MICROSOFT_SENTINEL_HUNT_AUTH_TYPE=azure_credential`). |
| Console | Azure portal: **Microsoft Entra ID > App registrations**, then the Log Analytics workspace of Microsoft Sentinel, **Access control (IAM)**. |
| Network | `login.microsoftonline.com` and `api.loganalytics.io` reachable from the connector. |

Step by step:

1. In **Microsoft Entra ID > App registrations > New registration**, register `opencti-hunt` (single tenant); note its **Directory (tenant) ID** and **Application (client) ID**.
2. In the app, **Certificates & secrets > New client secret**, and copy its value.
3. In the Log Analytics workspace, **Access control (IAM) > Add role assignment**: role **Log Analytics Reader** (or **Microsoft Sentinel Reader**), member `opencti-hunt`. Repeat on every workspace of `MICROSOFT_SENTINEL_HUNT_ADDITIONAL_WORKSPACES`.
4. Copy the **Workspace ID** from the **Overview** of the workspace.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Azure role `Log Analytics Reader` (or `Microsoft Sentinel Reader`) on the workspace | Run read-only queries on the workspace tables. |
| The same role on every workspace of `MICROSOFT_SENTINEL_HUNT_ADDITIONAL_WORKSPACES` | Cross-workspace queries. |

No API permission (Microsoft Graph or Log Analytics API) is required with an Azure role assignment, and the connector never writes to the workspace. The access token is requested for the `<api_url>/.default` scope.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
MICROSOFT_SENTINEL_HUNT_TENANT_ID=ChangeMe
MICROSOFT_SENTINEL_HUNT_CLIENT_ID=ChangeMe
MICROSOFT_SENTINEL_HUNT_CLIENT_SECRET=ChangeMe
MICROSOFT_SENTINEL_HUNT_WORKSPACE_ID=ChangeMe
```

A hunt run refused by the platform fails as **Access denied on** the platform, with the sentence of the connector naming the missing permission and what to grant.

Full configuration: [connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/internal-hunt/microsoft-sentinel-hunt/README.md).

### Microsoft Defender XDR

| | |
|---|---|
| Credential | A Microsoft Entra ID app registration with a client secret. |
| Console | Azure portal or Microsoft Entra admin center: **Microsoft Entra ID > App registrations**. Granting admin consent needs a Privileged Role Administrator, Cloud Application Administrator or Application Administrator. |
| Network | `login.microsoftonline.com` and `graph.microsoft.com` reachable from the connector. |

Step by step:

1. In **Microsoft Entra ID > App registrations > New registration**, register `opencti-hunt` (single tenant); note its **Directory (tenant) ID** and **Application (client) ID**.
2. In the app, **API permissions > Add a permission > Microsoft Graph > Application permissions**, select **ThreatHunting.Read.All**, then **Grant admin consent for &lt;tenant&gt;**.
3. In the app, **Certificates & secrets > New client secret**, and copy its value.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Microsoft Graph application permission `ThreatHunting.Read.All`, admin consent granted | Run read-only advanced hunting queries (`POST /security/runHuntingQuery`). |

No other permission and no Azure role is required, and the connector never writes to the tenant. The connector spends the advanced hunting quotas of the tenant (45 calls per minute, 1,500 per hour) at most at that pace, and reads at most 10,000 rows per query.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
MICROSOFT_DEFENDER_HUNT_TENANT_ID=ChangeMe
MICROSOFT_DEFENDER_HUNT_CLIENT_ID=ChangeMe
MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET=ChangeMe
```

A hunt run refused by the platform fails as **Access denied on** the platform, with the sentence of the connector naming the missing permission and what to grant.

Full configuration: [connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/internal-hunt/microsoft-defender-hunt/README.md).

### Elastic Security

| | |
|---|---|
| Credential | An Elasticsearch API key (or a user name and password) holding a dedicated role. |
| Console | Kibana: **Stack Management > Security > Roles** and **Stack Management > Security > API keys** (or `POST /_security/api_key`). |
| Network | The Elasticsearch HTTP API (port `9200` by default, or the Elastic Cloud endpoint) reachable from the connector. |

Step by step:

1. In **Stack Management > Roles > Create role**, create `opencti_hunt`: no cluster privilege; index privileges `read` and `view_index_metadata` on the indices of `ELASTIC_SECURITY_HUNT_INDICES`; for cross-cluster search, `read` as a remote index privilege.
2. In **Stack Management > API keys > Create API key**, restrict the key to the privileges of `opencti_hunt` (or call `POST /_security/api_key` with `role_descriptors` holding them).
3. Copy the `encoded` value of the key into `ELASTIC_SECURITY_HUNT_API_KEY`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Index privilege `read` on `ELASTIC_SECURITY_HUNT_INDICES` | Run ES\|QL, EQL and Lucene searches on the hunted data. |
| Index privilege `view_index_metadata` on the same indices | Resolve index patterns and field mappings. |
| Remote index privilege `read` (cross-cluster search only) | Hunt `remote:index` patterns. |

No cluster privilege is needed: the connector only deletes its own async searches, and never writes to the cluster.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
ELASTIC_SECURITY_HUNT_URL=https://elastic.example.com:9200
ELASTIC_SECURITY_HUNT_API_KEY=ChangeMe
ELASTIC_SECURITY_HUNT_INDICES=logs-*,winlogbeat-*
ELASTIC_SECURITY_HUNT_QUERY_LANGUAGE=esql
```

A hunt run refused by the platform fails as **Access denied on** the platform, with the sentence of the connector naming the missing permission and what to grant.

Full configuration: [connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/internal-hunt/elastic-security-hunt/README.md).

### CrowdStrike LogScale

| | |
|---|---|
| Credential | Falcon Next-Gen SIEM (`falcon`): an API client ID and secret. LogScale (`logscale`): a personal API token, or an organization token scoped to the repository. |
| Console | Falcon console: **Support and resources > API clients and keys**. LogScale: the API tokens of your account or organization. |
| Network | The Falcon API of your cloud (`https://api.crowdstrike.com`, `https://api.us-2.crowdstrike.com`, `https://api.eu-1.crowdstrike.com`...) or the LogScale URL. |

Step by step:

1. Falcon: in **Support and resources > API clients and keys > Create API client**, create `opencti-hunt` with the scope **NGSIEM**: Read and Write.
2. Copy the client ID and the secret (shown once) into `CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_ID` and `CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_SECRET`, and set `CROWDSTRIKE_LOGSCALE_HUNT_BASE_URL` to the API of your cloud.
3. LogScale instead: set `CROWDSTRIKE_LOGSCALE_HUNT_DEPLOYMENT=logscale`, create a token with search access to the repository (or view) of `CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY`, and set it with the URL in `CROWDSTRIKE_LOGSCALE_HUNT_LOGSCALE_TOKEN` and `CROWDSTRIKE_LOGSCALE_HUNT_LOGSCALE_URL`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| API client scope `NGSIEM` Read (`falcon`) | Read the status and results of the query jobs. |
| API client scope `NGSIEM` Write (`falcon`) | Start the query jobs and stop them. |
| Search (`ReadAccess` / `QueryDashboard`) on `CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY` (`logscale`) | Run query jobs on the repository or view. |

The connector never ingests nor modifies data: it only creates and deletes its own query jobs. With `falcon`, the API client credentials are exchanged for an OAuth2 token, renewed one minute before it expires.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
CROWDSTRIKE_LOGSCALE_HUNT_DEPLOYMENT=falcon
CROWDSTRIKE_LOGSCALE_HUNT_BASE_URL=https://api.crowdstrike.com
CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_ID=ChangeMe
CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_SECRET=ChangeMe
CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY=search-all
```

A hunt run refused by the platform fails as **Access denied on** the platform, with the sentence of the connector naming the missing permission and what to grant.

Full configuration: [connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/internal-hunt/crowdstrike-logscale-hunt/README.md).

### Google SecOps

| | |
|---|---|
| Credential | The JSON key of a Google Cloud service account. |
| Console | Google Cloud console: **APIs & Services > Library**, **IAM & Admin > Service accounts**, **IAM & Admin > IAM**; SecOps: **SIEM Settings > Profile**. |
| Network | `chronicle.googleapis.com` (or its regional endpoint) and `oauth2.googleapis.com` reachable from the connector. |

Step by step:

1. In the Google Cloud project of the SecOps instance, **APIs & Services > Library**: enable the **Chronicle API**.
2. In **IAM & Admin > Service accounts > Create service account**, create `opencti-hunt`.
3. In **IAM & Admin > IAM > Grant access**, give the service account the role **Chronicle API Editor** (`roles/chronicle.editor`), as for the other Google SecOps connectors; a custom role holding the UDM search and rule test permissions works as well.
4. In the service account, **Keys > Add key > Create new key > JSON**, and copy its `private_key`, `private_key_id`, `client_email`, `client_id` and `client_x509_cert_url` values into the configuration.
5. In SecOps, **SIEM Settings > Profile**: copy the project ID, the region (`us`, `europe`, `asia-southeast1`...) and the customer ID (instance UUID).

Least-privilege permissions:

| Permission | Why |
|---|---|
| Role `roles/chronicle.editor` (Chronicle API Editor) on the project | Run the UDM searches and test the YARA-L rules of the hunts: a test runs the rule over the window without saving it, enabling it or creating alerts. |
| Chronicle API enabled on the project | Every call of the connector goes through it. |

The connector only reads: it never saves, enables nor alerts on a rule.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
GOOGLE_SECOPS_HUNT_PROJECT_ID=my-project
GOOGLE_SECOPS_HUNT_PROJECT_REGION=us
GOOGLE_SECOPS_HUNT_PROJECT_INSTANCE=ChangeMe-instance-UUID
GOOGLE_SECOPS_HUNT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nChangeMe\n-----END PRIVATE KEY-----\n"
GOOGLE_SECOPS_HUNT_PRIVATE_KEY_ID=ChangeMe
GOOGLE_SECOPS_HUNT_CLIENT_EMAIL=opencti-hunt@my-project.iam.gserviceaccount.com
GOOGLE_SECOPS_HUNT_CLIENT_ID=ChangeMe
```

A hunt run refused by the platform fails as **Access denied on** the platform, with the sentence of the connector naming the missing permission and what to grant.

Full configuration: [connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/internal-hunt/google-secops-hunt/README.md).

### OpenSearch OCSF

| | |
|---|---|
| Credential | An internal user of the OpenSearch security plugin (HTTP basic authentication); none for a cluster without the security plugin. |
| Console | OpenSearch Dashboards: **Security > Roles** and **Security > Internal users**. |
| Network | The OpenSearch REST API (port `9200` by default) reachable from the connector. |

Step by step:

1. In **Security > Roles > Create role**, create `opencti_hunt`: cluster permission `cluster:admin/opensearch/ppl` (PPL only); index permissions `read` and `indices:admin/mappings/get` on the index patterns of `OPENSEARCH_OCSF_HUNT_INDICES`.
2. In **Security > Internal users > Create internal user**, create `svc_opencti_hunt` with a strong password.
3. Open the role `opencti_hunt`, tab **Mapped users > Manage mapping**, and map `svc_opencti_hunt`.
4. On Amazon OpenSearch Service, enable fine-grained access control and use a user of the internal user database.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Cluster permission `cluster:admin/opensearch/ppl` | Run PPL queries (not needed with `opensearch-lucene` only). |
| Index permission `read` on the index patterns of `OPENSEARCH_OCSF_HUNT_INDICES` | Search the OCSF events. |
| Index permission `indices:admin/mappings/get` on the same patterns | PPL reads the index mappings to resolve fields. |

Leave `OPENSEARCH_OCSF_HUNT_USERNAME` and `OPENSEARCH_OCSF_HUNT_PASSWORD` empty for a cluster without the security plugin.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
OPENSEARCH_OCSF_HUNT_URL=https://opensearch.example.com:9200
OPENSEARCH_OCSF_HUNT_USERNAME=svc_opencti_hunt
OPENSEARCH_OCSF_HUNT_PASSWORD=ChangeMe
OPENSEARCH_OCSF_HUNT_INDICES=ocsf-*
```

A hunt run refused by the platform fails as **Access denied on** the platform, with the sentence of the connector naming the missing permission and what to grant.

Full configuration: [connector README](https://github.com/OpenCTI-Platform/connectors/blob/master/internal-hunt/opensearch-ocsf-hunt/README.md).

## Registration

At startup a hunt connector registers its platform, the languages it executes and the **security platform** it executes against. The security platform is an Identity of type Security Platform (SIEM, EDR, XDR, SOAR, NDR, ISPM); it is created, with the declared type, when missing and once the registration is accepted. A registration never changes an existing security platform: its type and the rest are left to its editors. Hunts are scoped on security platforms, and the sightings OpenCTI keeps for the hunts are sighted on them.

Several connectors can serve the same platform type for different security platforms, for instance one Splunk connector per Splunk deployment. A hunt connector that names no security platform is refused.

Registered hunt connectors, their platform and their health are displayed in **Defense > Hunts** when creating a hunt, and in the connectors list, where the connector type reads **Internal hunt**. The page of a hunt connector (**Data > Ingestion > Connectors**) is the page of any connector: its state, its works and its configuration.

### Access denied

A hunt run refused by the platform (HTTP 401 or 403) fails as **Access denied on** the platform, with the sentence of the
connector naming what its account lacks and where to grant it (for example "Access denied: the roles of svc_opencti_hunt
lack the search capability: add it to one of its roles in Settings > Roles"), and a link to the connector.

![A run refused by Splunk: Access denied on the platform, the sentence of the connector naming what the account lacks, and Check the connector](assets/hunt-run-access-denied.png)

## Run lifecycle

1. OpenCTI pushes a run to the queue of the connector serving the security platform. The message carries the hunt (hypothesis, Sigma rules of a detection-rule hunt in `sigma_rules`, each with its `key`, `title`, `rule` and the `native_query` replacing it on the platform, techniques, targets, indicators; `sigma_rule` and `native_query` still carry the first rule and its native query for a connector that reads one rule), the markings and organizations of the run (`object_marking_refs`: those of the hunt and of the security platform, `granted_refs`: the organizations both are shared with), the time window and the limits (maximum results, timeout, evidence caps). A technique, target, indicator or author more restricted than the hunt (a marking the hunt does not cover, an organization of the hunt it is not shared with, or authorized members) is left out of the message: the connector never learns of it. A work tracks the run in the connector works.
2. The connector reports the run as `running`, translates each Sigma rule into the platform language (or takes its native query as is), and executes each over the time window: a rule that does not translate or fails is reported failed alone, the other rules still run. The native query of the platform is sent only when its language is one of the languages the connector registered; otherwise the connector translates the Sigma rule, or reports that it cannot.
3. When results are found, the connector sends a STIX bundle: an observable with its observed data for each value of the observables to extract from hits found in the results, among the types the connector supports (see [What a run produces](hunts.md#what-a-run-produces)). The identifiers are deterministic, so that re-runs update the knowledge instead of duplicating it. The objects attributed to the run carry its `object_marking_refs` and its `granted_refs`: an object attributed to a run that a user unable to read the run could read (a marking of the run it is not marked with at the same or a higher level, or, with a platform organization, an organization the run is not shared with, the organizations of the connector included when it cannot restrict access to organizations) is refused. A stored object is attributed to a run in a change of its own, its markings and organizations set before; an object of the bundle that upserts into a stored one is checked against the markings and organizations the stored one keeps, as an upsert only adds the incoming ones when its confidence allows it or to an empty field. Once stored, the evidence is shared like any object: a user allowed to change its markings or organizations decides who else reads it. The connector sends no sighting: OpenCTI keeps one sighting of each technique and indicator per security platform, whichever hunt found it, and one observed data per value or rule and victim, and updates them from the hit keys and the observations of each run.
4. The connector reports the run as `completed` with the hits count, the key of every hit it read (`hit_keys`, see below), the translated query, the evidence sample, the dates of the first and last matched event of the whole run when its hits sample is only a sample (`first_hit_at`, `last_hit_at`: without them, OpenCTI dates the sightings and the incident of the run from the sample) and whether the results are partial (`truncated`: shard failures, a partial API answer or an exhausted result budget, the hits count then being a lower bound, never the cap of the hits sample). It adds `rule_results`, one per Sigma rule of the message (`key`, `title`, `status` completed or failed, `hits_count`, `truncated`, `first_hit_at`, `last_hit_at`, `error`), and `observations`, every hit of the run grouped per value (indicator hunts) or rule (detection-rule hunts) and victim host (`key`, `host`, `hits_count`, `first_seen`, `last_seen`, `hit_keys`), which the observed data of the run follow. A report without them is still accepted: OpenCTI then reads the run as one rule and takes the observations from the value results or the run. The run is reported as `timeout` when the execution exceeded the run deadline, or as `failed` with the error. Failed and timed out runs are retried with the same backoff and never create knowledge. A terminal report can be sent again safely, for example when its answer was lost: the same outcome on a run already terminated returns the run as first reported, its hits counted once, while another outcome is refused.

### Hit keys

`hit_keys` lets OpenCTI count only the hits a hunt never saw on the platform (see [How hits are counted](hunts.md#how-hits-are-counted)). A connector computes one key per hit it read after benign suppression, sampled or not, bounded by the maximum results of the run, and reports the distinct keys. For an indicator hunt, each value result carries the keys of the hits holding the value (`hit_keys` of the result), which keeps the sighting of each indicator to its own hits. A lookup that returns counts instead of events reports no key: every hit of the run then counts as new.

The key is the SHA-256 hex digest of a compact JSON array (no spaces, UTF-8, characters not escaped) computed over the hit as the connector reports it in `hits_sample`, values exactly as sent, an empty string counting as absent:

| The hit has | Hashed array |
|---|---|
| A detection (the platform groups events into detections) | `["v1", "detection", <detection>]` |
| Else an event id | `["v1", "event", <event_id>]` |
| Else | `["v1", "fields", <timestamp to the second in UTC, "YYYY-MM-DDTHH:MM:SSZ", or "">, <host or "">, <user or "">, <process or "">, [[<field>, <value_hash in lower case>], ...]]`, the matched fields sorted by field then hash |

The security platform is not part of the key: OpenCTI keeps the known hits of a hunt per security platform. OpenCTI recomputes the key of each sampled hit with the same rule, and the connectors SDK computes it in `analysis.hit_key`; both assert the same test vectors.

For a query test, the connector translates the logic and reports the translated query without executing it.

OpenCTI only accepts the report of a run from the connector it was dispatched to, running as the user it ran as at the dispatch (a connector registered again as another user leaves its earlier runs to expire), never accepts a second report of a terminated run, and caps the evidence it stores. Raw values are never stored: the connectors SDK hashes each evidence value before sending it, and OpenCTI hashes again any value that does not arrive as a SHA-256 digest and masks the previews before storing them, so only a truncated, masked preview is kept.

## Developing a hunt connector

The Python library `pycti` provides the helpers of the hunt connector contract:

- `ConnectorType.INTERNAL_HUNT`, the connector type,
- `helper.register_hunt_platform(platform, languages, security_platform_name, security_platform_type, supports_preview, max_concurrent_runs, supports_indicators, required_permissions, documentation_url)`, the registration: `required_permissions` lists the permissions the account needs on the platform (`name` and `purpose` each) and `documentation_url` its setup documentation, both shown in the setup checklist of Defense > Hunts. A security platform is one product: several connectors of the same kind can execute against it, a connector of another kind naming it is refused, even when both register at the same time. A connector registered again against another security platform no longer receives the runs created for the former one: they are cancelled, and its reports on them are refused,
- `helper.listen_hunt(callback)`, the consumption of the runs (the callback receives the run message),
- `helper.report_hunt_run(run_id, status, ...)`, the run report, `hit_keys`, `first_hit_at`, `last_hit_at`, `rule_results` and `observations` included. It carries the work the run was dispatched with (by default the work of the message being processed): OpenCTI accepts the report of a dispatched run only with it, so that hunt connectors sharing a user cannot report each other's runs,
- `api.hunt` and `api.hunt_run`, the hunt and hunt run entities.

The connectors SDK provides an `InternalHuntConnector` base class and a template implementing the full lifecycle (deadline, Sigma translation through pySigma, result mapping to STIX, evidence hashing): a new platform only implements the query execution. It declares its `required_permissions` and `documentation_url`. Its API client (`HuntApiClient`) raises `HuntAccessDeniedError` on HTTP 401 and 403, with the `access_denied_hints` sentence of the connector naming what the account lacks.

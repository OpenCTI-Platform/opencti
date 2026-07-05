# Usage telemetry

The OpenCTI platform collects anonymous usage statistics related to its usage and sends them to Filigran. This data helps the development team understand how the platform is used and prioritize improvements.

!!! note "This is NOT observability telemetry"

    This page documents the **anonymous product analytics** sent to Filigran. If you are looking for **operational metrics** (API latency, request counts, error rates) to monitor your own deployment with Prometheus or an OTLP collector, see [Deployment > Telemetry](../deployment/telemetry.md).

!!! note "Confidentiality"

    The OpenCTI platform does not collect any information related to threat intelligence knowledge which remains strictly confidential. Also, the collection is strictly anonymous and personally identifiable information is NOT collected (including IP addresses).

All data collected is anonymized and aggregated to protect the privacy of individual users, in compliance with all privacy regulations.

## Purpose

The collected data is used for the following purposes:

- Improving the functionality and performance of the application.
- Analyzing user behavior to enhance user experience.
- Generating aggregated and anonymized statistics for internal and external reporting.

## How it works

The platform send the metrics to the hostname `telemetry.filigran.io` using the OTLP protocol (over HTTPS). The format of the data is OpenTelemetry JSON.

The metrics push is done every 6 hours if OpenCTI was able to connect to the hostname when the telemetry manager is started. Metrics are also written in specific log files in order to be included in support packages.

## Collected metrics

Here is an exhaustive list of the collected metrics:

### Platform information

- The current platform version
- The platform unique identifier
- The platform creation date
- The number of nodes in the cluster
- The deployment tags, when configured by the operator (`telemetry_manager:tags` / `TELEMETRY_MANAGER__TAGS` - comma-separated freeform tags such as `saas,eu-west`, normalized to lowercase and sorted before export)

### Users and accounts

- The number of users (excluding service accounts)
- The number of service accounts
- The number of user logins (session-based, does not count token authentication)
- The number of users turned into service accounts
- The number of service accounts turned into users
- The number of clicks on Forgot Password
- The number of background tasks on User scope

### Enterprise Edition

- Enterprise Edition status (activated or not)

### Connectors

- The number of active connectors
- The number of connectors deployed via composer
- The active connectors broken down by catalog identity: for composer-managed connectors, the catalog contract slug (resolved from the deployed container image), or the image repository path with the registry hostname stripped when the image is not part of the catalog; for manually registered connectors, the registered connector name - together with the connector type and a managed/manual flag. No connector configuration and no registry hostname is ever collected.

### Drafts

- The number of active drafts
- The number of draft creations
- The number of draft validations
- The number of roles with capability in draft
- The number of times the capabilities in draft tab is loaded

### Workbenches

- The number of active workbenches
- The number of workbench uploads (creation and updates)
- The number of workbench to draft conversions
- The number of workbench validations

### Features usage

- The number of dissemination feature usages
- The number of NLQ feature usages
- The number of request access creations (RFI of request access type)
- The number of custom views created
- The number of custom views enabled

### AI features

All AI usage counters are backend-agnostic: the same counter is incremented whether the feature is served by the legacy backend or by XTM One, and no counter carries a legacy/XTM One dimension.

- The number of chatbot messages sent
- The number of AI Insights requests, broken down by cache state (`hit`, `miss`)
- The number of Ask AI queries, broken down by feature (`fix_spelling`, `make_shorter`, `make_longer`, `change_tone`, `summarize`, `explain`, `container_report`, `summarize_files`, `convert_files_to_stix`, `activity`, `forecast`, `history`, `container_summary`)
- The number of direct XTM One agent calls, broken down by channel (`direct`, `direct_files`)
- The number of playbook AI agent component runs
- Whether the built-in LLM configuration is enabled, with the provider type as dimension (`mistralai`, `openai`, `azureopenai`, `other`, or `none` when disabled)
- Whether XTM One is configured (URL and token)
- Whether the Filigran chatbot AI CGU has been accepted

### Product adoption

- The number of knowledge objects, broken down by a curated list of entity types (reports, groupings, notes, opinions, cases, tasks, feedbacks, indicators, malware, intrusion sets, threat actors, incidents), plus the total number of observables and the total number of relationships. No knowledge content is ever collected, only counts.
- The number of built-in ingesters, broken down by type (`rss`, `taxii`, `taxii-collection`, `csv`, `json`) and running state
- The number of OpenCTI-to-OpenCTI synchronizers
- The number of data sharing surfaces, broken down by type (`live_stream`, `feed`, `taxii_collection`, `public_dashboard`) and public (anonymous access) state
- The number of playbooks, broken down by running state
- The number of playbook executions started
- The number of activated inference rules
- The number of notification triggers, broken down by type (`live`, `digest`)
- The number of notifiers, broken down by connector (`email`, `webhook`, `ui`, `other`)
- The number of notifications sent, broken down by channel (`email`, `webhook`, `ui`)
- The number of export generations requested
- The number of objects processed by completed import works (ingestion volume proxy)
- The number of groups
- The number of roles
- The number of organizations
- Whether organization segregation is configured
- Whether the file indexing manager is running
- The number of indexed files
- Whether the platform is registered on XTM Hub

### Email and notifications

- The number of emails sent from the platform
- The number of email templates created

### Form intakes

- The number of form intakes created
- The number of form intakes updated
- The number of form intakes deleted
- The number of form intakes submitted

### Security and compliance

- The number of security coverages
- The number of PIRs
- The number of decay rules created

### Retention and activity

- Whether the history retention rule is active on the platform
- Whether the activity retention rule is active on the platform
- Whether activity is enabled on the platform (has activity listeners configured)

### SSO providers configuration

- Whether Local authentication strategy is enabled
- Whether OpenID Connect strategy is enabled
- Whether LDAP strategy is enabled
- Whether SAML strategy is enabled
- Whether Auth0 strategy is enabled
- Whether Certificate strategy is enabled
- Whether Header strategy is enabled
- Whether Facebook strategy is enabled
- Whether Google strategy is enabled
- Whether GitHub strategy is enabled

### Workflows

- The number of workflow definitions published

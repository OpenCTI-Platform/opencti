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

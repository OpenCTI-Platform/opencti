# Usage telemetry

The application collects statistical data related to its usage and performances.

!!! note "Confidentiality"

    The OpenCTI platform does not collect any information related to threat intelligence knowledge which remains strictly confidential. Also, the collection is strictly anonymous and personally identifiable information is NOT collected (including IP addresses).

All data collected is anonymized and aggregated to protect the privacy of individual users, in compliance with all privacy regulations.

## Purpose of the telemetry

The collected data is used for the following purposes:

- Improving the functionality and performance of the application.
- Analyzing user behavior to enhance user experience.
- Generating aggregated and anonymized statistics for internal and external reporting.

## Important thing to know

The platform send the metrics to the hostname `telemetry.filigran.io` using the OTLP protocol (over HTTPS). The format of the data is OpenTelemetry JSON.

The metrics push is done every 6 hours if OpenCTI was able to connect to the hostname when the telemetry manager is started. Metrics are also written in specific logs files in order to be included in support package

## Telemetry metrics

The application collects statistical data related to its usage. Here are an exhaustive list of the collected metrics:

- The current platform version
- The platform unique identifier
- The platform creation date
- The number of active users
- The number of total users
- The number of nodes in the platform
- Enterprise Edition status (activated or not)
- The number of active connectors


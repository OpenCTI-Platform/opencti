# Data telemetry

The Application collects statistical data related to its usage.

Personally identifiable information is NOT collected by the Application. 

All data collected is anonymized and aggregated to protect the privacy of individual users.

## Purpose of telemetry

The collected data is used for the following purposes:

- Improving the functionality and performance of the application.
- Analyzing user behavior to enhance user experience.
- Generating aggregated and anonymized statistics for internal and external reporting.

## Important thing to know

The platform communicates the metrics through https://telemetry.filigran.io using the OTLP protocol. The format sent is the opentelemetry format in JSON.

The metric push is done every 6 hours if OpenCTI was able to communicate with the domain starting the telemetry manager.

Metrics are also written in specific logs files in order to be included in support package


## Telemetry metrics

The Application collects statistical data related to its usage, including exactly:

- The number of active users
- The number of total users
- The number of nodes in the platform
- Is enterprise edition is activated or not
- The number of active connectors


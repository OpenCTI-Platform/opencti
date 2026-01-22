# Telemetry

OpenCTI exposes metrics using the OpenTelemetry standard, which can be exported to various systems such as Prometheus or OTLP collectors. These metrics provide insights into the platform's performance, usage, and health.

## Configuration

To enable metrics, you need to configure the telemetry section in your platform configuration. See [Configuration](configuration.md#telemetry) for details on how to enable and configure exporters.

## Available Metrics

The following metrics are exposed by the OpenCTI API.

| Metric Name | Type | Description | Unit |
| :--- | :--- | :--- | :--- |
| `opencti_sent_email` | Counter | Counts the total number of emails sent by the platform. | Count |
| `opencti_api_requests` | Counter | Counts the total number of API requests received. | Count |
| `opencti_api_errors` | Counter | Counts the total number of API errors encountered. | Count |
| `opencti_api_latency` | Histogram | Measures the latency of API query execution. | Milliseconds |
| `opencti_api_direct_bulk` | Gauge | Measures the size of bulks for direct ingestion (fast path). | Count |
| `opencti_api_side_bulk` | Gauge | Measures the size of bulks for absorption impacts (worker path). | Count |

## Metric Attributes

Metrics exported by OpenCTI include various attributes (labels) to provide granular context.

### API Metrics Attributes
Applies to: `opencti_api_requests`, `opencti_api_errors`, `opencti_api_latency`

| Attribute | Description | Example |
|:---|:---|:---|
| `operation` | The GraphQL operation type. | `query`, `mutation`, `subscription` |
| `name` | The name of the GraphQL operation. | `StixCoreObjectFind`, `Unspecified` |
| `status` | The outcome of the request. | `SUCCESS`, `ERROR` |
| `type` | The error type (only present if status is ERROR). | `AUTH_REQUIRED`, `FORBIDDEN_ACCESS` |
| `user_agent` | The client user agent initiating the request. | `Mozilla/5.0...`, `OpenCTI-Client` |

### Email Metrics Attributes
Applies to: `opencti_sent_email`

| Attribute | Description | Example |
|:---|:---|:---|
| `category` | The functional category of the email. | `hub-registration`, `dissemination`, `password-reset`, `notification` |
| `identifier` | The ID of the related entity (e.g., user, trigger, list). | `uuid-v4-string` |

### Bulk Metrics Attributes
Applies to: `opencti_api_direct_bulk`, `opencti_api_side_bulk`

| Attribute | Description | Example |
|:---|:---|:---|
| `type` | The context or source of the indexing operation. | `import`, `connector` |

## Node.js Runtime Metrics

In addition to the application-specific metrics above, OpenCTI also exposes standard Node.js runtime metrics provided by `opentelemetry-node-metrics`. These include metrics for:

- **Process**: CPU usage, memory usage, uptime, etc.
- **Event Loop**: Lag, active handles, etc.
- **GC**: Garbage collection duration and counts.
- **Memory**: Heap usage, heap limits, etc.

Common examples include:
- `process_cpu_user_seconds_total`
- `process_cpu_system_seconds_total`
- `process_resident_memory_bytes`
- `nodejs_eventloop_lag_seconds`
- `nodejs_gc_duration_seconds`

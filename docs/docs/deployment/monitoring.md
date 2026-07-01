# Monitoring & observability

This guide provides operational guidance for monitoring a production OpenCTI deployment. The [Telemetry](telemetry.md) page documents *what* metrics exist and *how* to enable them; this page focuses on *what to watch*, how to organise dashboards, and how to correlate symptoms across layers.

!!! tip "Start with telemetry enabled"

    Make sure metrics are enabled and exported before relying on this guide. See [Telemetry](telemetry.md) for the platform metrics and [Configuration](configuration.md#telemetry) for the exporter options (Prometheus scrape endpoint or OTLP). Worker and connector telemetry is configured in their respective sections.

## The three layers to monitor

A production OpenCTI deployment should be observed across three layers. Most incidents are diagnosed by correlating a symptom in one layer with a root cause in another.

| Layer | Components | Examples of what to watch |
| :--- | :--- | :--- |
| **Application** | Platform API, workers, connectors | API latency and errors, ingestion throughput, worker saturation, connector health |
| **Infrastructure** | ElasticSearch/OpenSearch, Redis, RabbitMQ, S3/MinIO | Cluster health, disk watermarks, Redis memory, queue depth |
| **Host / orchestrator** | Kubernetes, Docker, VMs | CPU, memory, disk, pod restarts, OOM kills |

## Application layer

OpenCTI exposes native OpenTelemetry metrics for the platform API. The most useful ones for day-to-day operations are:

| Metric | What it tells you |
| :--- | :--- |
| `opencti_api_requests` | Overall API traffic. Sudden drops can indicate an outage upstream; spikes can explain latency. |
| `opencti_api_errors` | API errors, broken down by `type` (e.g. `AUTH_REQUIRED`, `FORBIDDEN_ACCESS`). A rising error rate is an early warning. |
| `opencti_api_latency` | Query execution latency (histogram). Track the p95/p99, not just the average. |
| `opencti_api_direct_bulk` / `opencti_api_side_bulk` | Ingestion bulk sizes for the direct (fast) path and the worker path. Useful to understand ingestion pressure. |
| `opencti_sent_email` | Outbound email volume by `category`. Useful to confirm notifications/digests are being delivered. |

In addition, the platform exposes standard Node.js runtime metrics (CPU, memory, event-loop lag, GC) — see [Telemetry](telemetry.md#nodejs-runtime-metrics). A sustained rise in `nodejs_eventloop_lag_seconds` usually means the platform node is saturated.

!!! note "Workers and connectors"

    Workers and connectors are the ingestion engine. Watch worker throughput against the RabbitMQ queue depth: if the queue grows while workers are busy, you are ingestion-bound and may need more workers or more ElasticSearch capacity. If the queue grows while workers are *idle*, look for a downstream problem (for example a flushed Redis — see [Troubleshooting](advanced/troubleshooting.md)).

## Infrastructure layer

OpenCTI's behaviour is tightly coupled to its dependencies. Monitor each one directly:

- **ElasticSearch / OpenSearch** — cluster status (green/yellow/red), disk usage against the flood-stage watermark, JVM heap pressure, rejected writes and merge activity. Disk filling up is the single most common cause of ingestion stalls (`TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark`).
- **Redis** — memory usage against `maxmemory`, blocked clients and the slowlog. Redis holds critical platform state; see the Redis section in [Troubleshooting](advanced/troubleshooting.md) for why it must never be flushed.
- **RabbitMQ** — queue depth and consumer count per connector. A persistently growing queue means consumption is not keeping up with production.
- **S3 / MinIO** — availability and storage capacity for file storage and exports.

## Host / orchestrator layer

Standard infrastructure monitoring applies: CPU, memory, disk, and network for each node, plus pod restart counts and OOM kills on Kubernetes. Correlate restarts with application errors — a crash-looping platform pod will surface as a sudden drop in `opencti_api_requests`.

## Suggested dashboard structure

OpenCTI does not ship pre-built Grafana dashboards. A practical starting point is to organise panels by operational concern rather than by metric source:

1. **API health** — request rate, error rate (by `type`), p95/p99 latency.
2. **Ingestion throughput** — bulk sizes, worker throughput, RabbitMQ queue depth.
3. **Worker & connector health** — consumer counts, connector run state, retries.
4. **Platform runtime** — Node.js CPU/memory, event-loop lag, GC.
5. **Infrastructure** — ElasticSearch cluster status and disk, Redis memory, RabbitMQ queues.

## Setting baselines and alerts

Healthy ranges are deployment-specific — they depend on data volume, number of connectors, hardware, and ElasticSearch sizing. Rather than relying on absolute numbers, capture a baseline during normal operation and alert on **deviations from that baseline** and on trends, for example:

- Error rate rising above its normal range, or any sustained increase.
- p95 latency trending upward over time.
- RabbitMQ queue depth growing without draining.
- ElasticSearch disk approaching the flood-stage watermark.
- Redis memory approaching `maxmemory`.
- Platform/worker pods restarting repeatedly.

Combining an application-layer alert (for example rising latency) with the infrastructure panels usually points directly at the root cause (for example ElasticSearch disk pressure or Redis memory exhaustion).

# Liveness probe

This page explains how to configure the OpenCTI liveness probe, a lightweight HTTP endpoint that reports whether the platform process is running.

## What is the liveness probe?

The liveness probe is a dedicated HTTP server that starts **immediately** when the OpenCTI process launches, before any platform initialization (database migrations, dependency checks, cache warm-up, etc.). It responds with HTTP 200 OK to indicate that the process is alive.

This is distinct from the existing `/health` readiness endpoint, which only becomes available after the full platform has started and checks all backend dependencies (ElasticSearch, Redis, RabbitMQ, S3).

## Why use it?

Container orchestrators like **Kubernetes** need to distinguish between two states:

- **Liveness** — Is the process running? If not, restart the container.
- **Readiness** — Is the application ready to serve traffic? If not, stop sending requests.

| Probe     | Endpoint                      | Port                                   | Available                          | Checks                             |
|:----------|:------------------------------|:---------------------------------------|:-----------------------------------|:-----------------------------------|
| Liveness  | `{base_path}/health/liveness` | `app:liveness_port` (default disabled) | Immediately on process start       | Process is running                 |
| Readiness | `{base_path}/health`          | `app:port` (default `4000`)            | After full platform initialization | ElasticSearch, Redis, RabbitMQ, S3 |

## What's next?

- [Configuration](../configuration.md) — Full list of platform configuration parameters.
- [Clustering](clustering.md) — Deploy multiple OpenCTI instances with health monitoring.
- [Troubleshooting](troubleshooting.md) — Diagnose startup and connectivity issues.


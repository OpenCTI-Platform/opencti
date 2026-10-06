# OpenCTI analytics process

`opencti-analytics` computes graph analytics that do not fit in the platform at scale: connected
components, communities (label propagation) turned into infrastructure, campaign and tooling clusters,
and approximate betweenness centrality. It reads the knowledge graph through the GraphQL API and writes
the results back with the `graphAnalyticsUpsertMetrics` mutation. It never creates or modifies STIX
objects or relationships.

The platform itself runs a graph analytics manager (degree metrics, structural similarity, infrastructure
clustering). On small platforms this is enough: the process skips its runs below `min_edges` edges and the
manager keeps the clusters. When the process writes results, the platform stops computing clusters for
`graph_analytics_manager:analytics_process_grace_hours` (48 hours by default) and the process owns them.

## How it works

1. Count the edges of the configured relationship types (`graphAnalyticsEdges`), skip the run below
   `min_edges` unless `force` is set.
2. Fetch the edges page by page as compact `(from, to, type)` records, ids only. Containment (`object`) edges
   of containers larger than `max_container_size` are dropped, nodes above `max_node_degree` are ignored as
   hubs for community detection.
3. Compute connected components, label propagation communities (seeded, deterministic) and approximate
   betweenness on `betweenness_sample_size` sampled sources, with igraph, or networkx as a fallback.
4. Classify each community (infrastructure, campaign or tooling) and keep those between `min_cluster_size`
   and `max_cluster_size` members. Cluster identifiers are deterministic, so a cluster keeps its identity,
   and its promotions to Groupings or Campaigns, from one run to the next.
5. Write the metrics and clusters back in batches; the last call completes the run, which detaches the
   entities and removes the clusters of older runs.

Every query runs with the service account: the process only sees, and only writes on, what this account
can access. Completing a run replaces the clusters and run metrics of the whole platform, so the platform only
accepts it from an account that bypasses data restrictions: give the process a dedicated user whose role grants
`Bypass all capabilities` (`BYPASS`). A run whose edges export stops early (pagination without progress, or more
than `max_edges` edges) fails without completing.

## Run with Docker

```yaml
services:
  opencti-analytics:
    image: opencti/analytics:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ANALYTICS_TOKEN}
      - ANALYTICS_RUN_INTERVAL_HOURS=24
      - ANALYTICS_MIN_EDGES=50000
    depends_on:
      opencti:
        condition: service_healthy
    restart: always
```

To run a single analysis from a scheduler (cron, Kubernetes `CronJob`), override the command:
`command: ["analytics.py", "--once"]`. Add `--force` to run below `min_edges`.

## Run from the sources

The process requires Python 3.12 or later, the version of its Docker images.

```bash
cd opencti-analytics
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.yml.sample src/config.yml   # read next to analytics.py; then set opencti.url and opencti.token
cd src
python analytics.py --once --force
```

## Configuration

Values come from `config.yml` (see `config.yml.sample`), environment variables win.

| Parameter | Environment variable | Default | Description |
|---|---|---|---|
| `opencti.url` | `OPENCTI_URL` | (required) | URL of the OpenCTI platform |
| `opencti.token` | `OPENCTI_TOKEN` | (required) | API token of the service account |
| `opencti.ssl_verify` | `OPENCTI_SSL_VERIFY` | `true` | Verify the platform certificate (set `false` only for a self-signed certificate: the token sent has Bypass privileges) |
| `opencti.json_logging` | `OPENCTI_JSON_LOGGING` | `true` | Log in JSON |
| `opencti.requests_timeout` | `OPENCTI_REQUESTS_TIMEOUT` | `300` | API request timeout, in seconds |
| `opencti.custom_headers` | `OPENCTI_CUSTOM_HEADERS` | | Extra HTTP headers (`name:value;name:value`) |
| `analytics.log_level` | `ANALYTICS_LOG_LEVEL` | `info` | Log level |
| `analytics.enabled` | `ANALYTICS_ENABLED` | `true` | Disable to keep the process idle |
| `analytics.run_interval_hours` | `ANALYTICS_RUN_INTERVAL_HOURS` | `24` | Hours between two runs |
| `analytics.run_on_start` | `ANALYTICS_RUN_ON_START` | `true` | Run immediately at start |
| `analytics.min_edges` | `ANALYTICS_MIN_EDGES` | `50000` | Skip runs below this number of edges |
| `analytics.force` | `ANALYTICS_FORCE` | `false` | Run whatever the number of edges |
| `analytics.relationship_types` | `ANALYTICS_RELATIONSHIP_TYPES` | `communicates-with, resolves-to, consists-of, uses, attributed-to, related-to, based-on, object` | Relationship types analyzed (comma separated in the environment) |
| `analytics.include_inferred` | `ANALYTICS_INCLUDE_INFERRED` | `false` | Include inferred relationships |
| `analytics.max_edges` | `ANALYTICS_MAX_EDGES` | `5000000` | Maximum number of edges loaded in memory |
| `analytics.max_container_size` | `ANALYTICS_MAX_CONTAINER_SIZE` | `500` | Containers above this size are not used to link their objects |
| `analytics.max_node_degree` | `ANALYTICS_MAX_NODE_DEGREE` | `10000` | Hubs above this degree do not merge communities |
| `analytics.min_cluster_size` | `ANALYTICS_MIN_CLUSTER_SIZE` | `3` | Smallest cluster kept |
| `analytics.max_cluster_size` | `ANALYTICS_MAX_CLUSTER_SIZE` | `5000` | Largest cluster kept |
| `analytics.betweenness_sample_size` | `ANALYTICS_BETWEENNESS_SAMPLE_SIZE` | `500` | Sampled sources for the approximate betweenness (0 disables it) |
| `analytics.betweenness_cutoff` | `ANALYTICS_BETWEENNESS_CUTOFF` | | Maximum path length considered by the betweenness |
| `analytics.batch_size` | `ANALYTICS_BATCH_SIZE` | `2000` | Entity metrics per write-back call (at most 5000) |
| `analytics.cluster_batch_size` | `ANALYTICS_CLUSTER_BATCH_SIZE` | `200` | Clusters per write-back call (at most 1000) |
| `analytics.engine` | `ANALYTICS_ENGINE` | `auto` | `auto`, `igraph` or `networkx` |
| `analytics.seed` | `ANALYTICS_SEED` | `42` | Seed of the community detection, for reproducible clusters |
| `analytics.telemetry_enabled` | `ANALYTICS_TELEMETRY_ENABLED` | `false` | Expose Prometheus metrics |
| `analytics.telemetry_prometheus_port` | `ANALYTICS_TELEMETRY_PROMETHEUS_PORT` | `14271` | Prometheus port |
| `analytics.telemetry_prometheus_host` | `ANALYTICS_TELEMETRY_PROMETHEUS_HOST` | `0.0.0.0` | Prometheus host |

## Development

```bash
cd opencti-analytics
pip install -r requirements.txt -r test-requirements.txt
python -m pytest
black --check . && isort --check-only . && flake8 .
```

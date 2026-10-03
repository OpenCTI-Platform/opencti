# Graph analytics

This page explains how the [graph analytics](../usage/graph-analytics.md) (paths, similarity, clusters and graph metrics) are computed, how to tune them, and when to deploy the optional analytics process.

## Architecture

Graph analytics rely on two components:

- The **graph analytics manager**, part of the platform and enabled by default. It computes the degree of every entity, the top similar entities of the profiled entity types, and the infrastructure clusters. Path queries are computed on demand by the API, as the requesting user.
- The **analytics process** (`opencti-analytics`), optional, for large platforms. It loads the knowledge graph in memory to detect communities, build infrastructure, campaign and tooling clusters, and compute the approximate betweenness of every entity, then writes the results back through the API.

Analytics never create or modify STIX objects or relationships. The metrics are stored in the `x_opencti_graph_metrics` attribute of the entities and the similarities in a dedicated `graph_similarity` index; both contain identifiers only. They are written without generating stream events nor changing the modification date of the entities.

## Graph analytics manager

The manager runs on one platform node at a time (it uses a lock). On each run it:

1. Reads the stream to find the entities whose relationships changed, and queues them.
2. Recomputes the queued entities once they have not changed for the debounce delay (one minute by default), and the entities whose similarity was explicitly refreshed by a user.
3. Once a day, at the configured hour, refreshes the degree of every entity in time-boxed steps, queues the entities whose similarity is outdated, then recomputes the infrastructure clusters. On a platform never analyzed, for instance after an upgrade, this full pass starts immediately.

While the analytics process wrote results in the last `analytics_process_grace_hours`, the manager leaves the clusters to it.

### Configuration

| Parameter | Environment variable | Default | Description |
|---|---|---|---|
| `graph_analytics_manager:enabled` | `GRAPH_ANALYTICS_MANAGER__ENABLED` | `true` | Enable the graph analytics manager |
| `graph_analytics_manager:interval` | `GRAPH_ANALYTICS_MANAGER__INTERVAL` | `30000` | Delay between two runs, in milliseconds |
| `graph_analytics_manager:debounce_ms` | `GRAPH_ANALYTICS_MANAGER__DEBOUNCE_MS` | `60000` | Quiet delay before an entity that changed is recomputed, in milliseconds |
| `graph_analytics_manager:max_entities_per_tick` | `GRAPH_ANALYTICS_MANAGER__MAX_ENTITIES_PER_TICK` | `200` | Entities recomputed per run |
| `graph_analytics_manager:full_pass_hour` | `GRAPH_ANALYTICS_MANAGER__FULL_PASS_HOUR` | `2` | Hour (UTC) of the nightly full pass |
| `graph_analytics_manager:full_pass_batch_size` | `GRAPH_ANALYTICS_MANAGER__FULL_PASS_BATCH_SIZE` | `1000` | Entities read per step of the full pass |
| `graph_analytics_manager:full_pass_max_entities` | `GRAPH_ANALYTICS_MANAGER__FULL_PASS_MAX_ENTITIES` | `2000000` | Maximum number of entities of a full pass |
| `graph_analytics_manager:similarity_top_n` | `GRAPH_ANALYTICS_MANAGER__SIMILARITY_TOP_N` | `20` | Similar entities kept per entity |
| `graph_analytics_manager:similarity_min_score` | `GRAPH_ANALYTICS_MANAGER__SIMILARITY_MIN_SCORE` | `0.05` | Minimum score of a kept similarity |
| `graph_analytics_manager:similarity_max_candidates` | `GRAPH_ANALYTICS_MANAGER__SIMILARITY_MAX_CANDIDATES` | `200` | Candidates scored per entity |
| `graph_analytics_manager:feature_max_fanout` | `GRAPH_ANALYTICS_MANAGER__FEATURE_MAX_FANOUT` | `500` | Elements shared by more entities are not used to find candidates |
| `graph_analytics_manager:feature_max_per_family` | `GRAPH_ANALYTICS_MANAGER__FEATURE_MAX_PER_FAMILY` | `500` | Elements kept per family in an entity profile |
| `graph_analytics_manager:clustering_enabled` | `GRAPH_ANALYTICS_MANAGER__CLUSTERING_ENABLED` | `true` | Compute infrastructure clusters in the platform |
| `graph_analytics_manager:clustering_max_entities` | `GRAPH_ANALYTICS_MANAGER__CLUSTERING_MAX_ENTITIES` | `100000` | Maximum number of infrastructure elements clustered |
| `graph_analytics_manager:clustering_feature_max_fanout` | `GRAPH_ANALYTICS_MANAGER__CLUSTERING_FEATURE_MAX_FANOUT` | `50` | Features shared by more elements do not link them |
| `graph_analytics_manager:clustering_min_size` | `GRAPH_ANALYTICS_MANAGER__CLUSTERING_MIN_SIZE` | `3` | Smallest cluster kept |
| `graph_analytics_manager:analytics_process_grace_hours` | `GRAPH_ANALYTICS_MANAGER__ANALYTICS_PROCESS_GRACE_HOURS` | `48` | Hours during which the analytics process owns the clusters after its last run |
| `graph_analytics:path_default_depth` | `GRAPH_ANALYTICS__PATH_DEFAULT_DEPTH` | `4` | Default maximum path length |
| `graph_analytics:path_max_depth` | `GRAPH_ANALYTICS__PATH_MAX_DEPTH` | `6` | Highest maximum path length a user can request |
| `graph_analytics:path_max_paths` | `GRAPH_ANALYTICS__PATH_MAX_PATHS` | `20` | Highest number of paths a user can request |
| `graph_analytics:path_timeout_ms` | `GRAPH_ANALYTICS__PATH_TIMEOUT_MS` | `15000` | Time limit of a path search, in milliseconds |
| `graph_analytics:path_max_expanded_nodes` | `GRAPH_ANALYTICS__PATH_MAX_EXPANDED_NODES` | `20000` | Entities explored by a path search |
| `graph_analytics:path_max_relationships_per_level` | `GRAPH_ANALYTICS__PATH_MAX_RELATIONSHIPS_PER_LEVEL` | `20000` | Relationships read per step of a path search |
| `graph_analytics:similarity_max_results` | `GRAPH_ANALYTICS__SIMILARITY_MAX_RESULTS` | `100` | Similar entities returned per query |
| `graph_analytics:matrix_max_entities` | `GRAPH_ANALYTICS__MATRIX_MAX_ENTITIES` | `25` | Entities of a similarity matrix |

## Analytics process

### When to deploy it

The manager covers most platforms. Deploy the analytics process when your knowledge graph holds more than about 50,000 relationships of the analyzed types and you want communities beyond shared infrastructure features, campaign and tooling clusters, or the approximate betweenness of entities. Below its `min_edges` threshold the process skips its runs and the manager keeps the clusters.

The process keeps the analyzed graph in memory (identifiers only): size its memory according to the number of analyzed relationships, `ANALYTICS_MAX_EDGES` being the safety limit.

### Service account

Create a dedicated user for the process, with a role granting **Bypass all capabilities**. Completing a run replaces the clusters and run metrics of the whole platform, so the platform refuses it from an account restricted by markings, organizations or authorized members: such an account would detach entities it never analyzed. The process only reads identifiers and types, and only writes graph metrics and clusters. A run whose edges export stops early fails without completing, and the previous results stay in place.

### Docker deployment

Add the service to your `docker-compose.yml`:

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

To run it from a scheduler instead (cron, Kubernetes `CronJob`), use the `analytics.py --once` command: the process runs one analysis and exits.

### Configuration

| Environment variable | Default | Description |
|---|---|---|
| `OPENCTI_URL` | (required) | URL of the OpenCTI platform |
| `OPENCTI_TOKEN` | (required) | API token of the service account |
| `ANALYTICS_ENABLED` | `true` | Disable to keep the process idle |
| `ANALYTICS_RUN_INTERVAL_HOURS` | `24` | Hours between two runs |
| `ANALYTICS_RUN_ON_START` | `true` | Run immediately at start |
| `ANALYTICS_MIN_EDGES` | `50000` | Skip the runs below this number of relationships |
| `ANALYTICS_FORCE` | `false` | Run whatever the number of relationships |
| `ANALYTICS_RELATIONSHIP_TYPES` | `communicates-with,resolves-to,consists-of,uses,attributed-to,related-to,based-on,object` | Relationship types analyzed, `object` being the content of containers |
| `ANALYTICS_INCLUDE_INFERRED` | `false` | Include inferred relationships |
| `ANALYTICS_MAX_EDGES` | `5000000` | Maximum number of relationships loaded |
| `ANALYTICS_MAX_CONTAINER_SIZE` | `500` | Larger containers do not link their objects |
| `ANALYTICS_MAX_NODE_DEGREE` | `10000` | Hubs above this degree do not merge communities |
| `ANALYTICS_MIN_CLUSTER_SIZE` | `3` | Smallest cluster kept |
| `ANALYTICS_MAX_CLUSTER_SIZE` | `5000` | Largest cluster kept |
| `ANALYTICS_BETWEENNESS_SAMPLE_SIZE` | `500` | Sampled sources of the approximate betweenness, `0` disables it |
| `ANALYTICS_ENGINE` | `auto` | Graph library: `auto`, `igraph` or `networkx` |
| `ANALYTICS_SEED` | `42` | Seed of the community detection, for reproducible clusters |
| `ANALYTICS_TELEMETRY_ENABLED` | `false` | Expose Prometheus metrics on `ANALYTICS_TELEMETRY_PROMETHEUS_PORT` (`14271`) |

The full list of parameters is available in the `opencti-analytics/README.md` file of the OpenCTI repository.

## Monitoring

**Analyses > Graph clusters** shows whether the analytics are enabled, who computes the clusters, the number of clusters and similarity links, the entities waiting for a recompute and the date of the last full pass and of the last analytics process run.

# PoC: isolated backend integration tests with testcontainers — outcome

Status: **phase 0 done** (baseline and measurements). Phases 1 to 5 are planned, not started.
Branch: `poc-testcontainers`. Measured on 2026-10-22.

## Outcome in short

- **The original idea was a new set of containers (ES, Redis, RabbitMQ, MinIO) per test suite.** That is too expensive for `03-integration`. A full stack takes ~8.5 s to be ready locally, and ES alone ~14 s on CI. The median `03` file runs in 0.4–0.6 s.
- **Running in parallel doesn't make up for the startup.** It divides the test time and the startup time by the same number of workers, so per-file startup stays an added cost.
- **Isolation can come from prefixes instead.** OpenCTI already namespaces every backend from configuration: ES index prefix, Redis namespace (keys, streams and pub/sub topics), RabbitMQ queue prefix and MinIO bucket. The core of the PoC is now **one prefix per test file** on shared backends.
- **Pre-seeded state is required either way.** A fresh prefix or container needs 40–50 s of initialization before its first test.
- **Testcontainers remains useful, but as an optional layer.** It can start the backends from code, provide seeded data directories, and serve tests that need a cluster of their own. See [Where testcontainers is worth it](#where-testcontainers-is-worth-it).

## Why the tests are not isolated today

1. `vitest.config.integration.ts` runs `maxWorkers: 1`, `isolate: false` with a sorted sequencer. `tests/setup/globalSetup.ts` wipes and re-initializes a single `test` prefix, and every file inherits what earlier files left behind. `02-dataInjection/00-inject/loader-test.ts` loads the dataset that `02-dataInjection/01-dataCount` and much of `03-integration` depend on.
2. `tests/utils/syncCountHelper.ts` holds totals for every entity created by any test, and the `11-sync` suites check them against remote platforms.
3. `globalSetup` starts the managers (rule engine, history, task scheduler, connector manager) in the main vitest process, while the tests run in a worker against the same store.
4. Part of the configuration is read at import time: the MinIO and RabbitMQ settings, `REDIS_PREFIX` and `TOPIC_PREFIX` (`src/config/conf.js`). Per-file settings, whether ports or prefixes, need a fresh module graph per file.

## Baseline: current CI

Source: the 12 most recent successful `ci-main` runs on `master` (2026-10-21 23:01 → 2026-10-22 15:02 UTC). Per-file times come from the vitest output of 2 of those runs.

The "Integration tests" job runs `test:ci-integration-sync` (`02|03|10|11`), not `test:ci-integration`.

| Job | Job total (min / median / max) | Test step (min / median / max) |
|---|---|---|
| Backend / Integration tests | 1003 / **1356** / 1441 s | 800 / **1112** / 1159 s |
| Backend / Rules and Taxii tests | 583 / **630** / 670 s | 480 / **521** / 541 s |

Where the time goes in the Integration test step:

| Phase | Time |
|---|---|
| Before vitest (copy `node_modules`, `yarn install:python`) | 38–44 s |
| `globalSetup`: platform init (`initializePlatform`) | 17.5 s |
| `globalSetup`: `createTestUsers` | 10.8 s |
| `02/00-inject` (dataset load) | 10–14 s |
| `02` other suites (4 files) | 23–36 s |
| `03-integration` (231 files, 2589 tests) | **286–407 s**; per file median 0.4–0.6 s, p90 4.5–5.8 s |
| `10-streams` (2 files) | 74–76 s |
| `11-sync` (4 files) | **327–461 s** |

In the Rules job, `20-rules` takes 344 s for 9 files (≈ 38 s per file). Init and test users take 20.4 s + 15.6 s there.

CI runner resources (`docker stats` / `free -m` in the job logs):
- 16 GB of RAM, with peak usage of 6.3 GB (Rules) and 9.6 GB (Integration).
- ES (2G heap) uses 2.6–2.8 GiB and the test process 2.4–2.8 GiB.
- RabbitMQ uses ~125 MiB, MinIO 76–167 MiB, Redis 8–21 MiB.

ES startup on CI (compose logs, 6 runs): cold image pulls take 14–23 s, container creation ~9 s, then *started → cluster yellow* **12–18 s** (median 14 s).

## Backend startup and memory via testcontainers (local)

Script: `script/poc-testcontainers-measure.ts`. It uses the same images and settings as `scripts/ci/docker-compose.yml` and starts each backend 3 times. "Ready" means the wait strategy passed (ES: `_cluster/health?wait_for_status=yellow`). Memory is measured as `docker stats` does, after a 15 s settle.

Environment: MacBook, Podman 6.1 machine (applehv, Fedora arm64, 5 vCPU, 21.8 GiB), Node 22.23.3, testcontainers 12.2.0.

| Backend | Ready (min / median / max) | RAM after settle (median) |
|---|---|---|
| ES 8.19.23, 2G heap (as CI) | 8.5 / **8.5** / 13.7 s | **2481 MiB** |
| ES 8.19.23, 512m heap | 7.3 / **7.3** / 8.5 s | **922 MiB** |
| Redis 8.6.7 | 0.16 / **0.16** / 0.18 s | 6 MiB |
| RabbitMQ 4.3-management | 2.8 / **3.0** / 3.3 s | 130 MiB |
| MinIO (`pgsty/silo:latest`) | 1.27 / **1.27** / 1.27 s | 71 MiB |
| **Full stack in parallel** (ES 512m + Redis + RabbitMQ + MinIO) | 8.5 / **8.6** / 8.6 s | **1126 MiB** |

Cold pulls on the laptop: ES 257 s, RabbitMQ 38 s.

ES with a 512m heap starts as fast as with 2G and uses 2.7× less memory. Whether the test workload fits in 512m is still to be checked.

## Per-suite containers against parallelism

With `F` files, `W` seconds of total test work, `s` seconds of stack startup, `r` seconds of reset and `N` workers:

- New stack per file: wall ≈ (W + F × s) / N
- One stack per worker, reset between files: wall ≈ W / N + s + F × r / N

Both get the same N-fold speedup, so per-file startup is an extra cost that parallelism only spreads. For `03-integration` (F = 231, W ≈ 350 s):

- Startup alone is 231 × 8.5 s ≈ 33 min locally, and ≈ 54 min at CI's ~14 s.
- With 3 workers, that's still 11–18 min of startup, against 5–7 min for the whole sequential run today.
- Breaking even needs N ≥ 1 + F × s / W: about 7 workers locally, about 10 on CI. That's 25–35 GB of RAM (~1.1 GiB per stack plus ~2.5 GiB per test process) on a 16 GB runner, just to break even.
- Not counted: CPU contention between ES instances starting together, and loading a seed into every new container.

For `20-rules` the numbers flip. Its 9 files take ~38 s each, so 8.5 s of startup is ~22% overhead, and 3 workers would bring 344 s down to ~140 s.

The testcontainers guidance points the same way:
- Docker's [Testcontainers best practices](https://www.docker.com/blog/testcontainers-best-practices/) call separate containers per test "resource-intensive", say they "may slow down the test execution", and recommend sharing a container per test class or using the [singleton containers pattern](https://docs.docker.com/guides/testcontainers-java-lifecycle/singleton-containers.md).
- The Node [global setup](https://node.testcontainers.org/quickstart/global-setup/) page suggests, for slow-starting services, running one instance and managing state between tests.

## Isolation with prefixes

OpenCTI already namespaces each backend from configuration:
- ES indices, index templates, component templates and the ILM policy follow the index prefix.
- Redis keys and streams go through clients created with `keyPrefix: REDIS_PREFIX`.
- Redis pub/sub topics are built from `TOPIC_PREFIX`.
- RabbitMQ queues and exchanges follow `queue_prefix`.
- MinIO uses the configured `bucket_name`.

Per-worktree test runs already work this way. One prefix per test file therefore gives data isolation with no container startup.

Caveats:
- **The prefix is read at import time.** Each file needs a fresh module graph (`pool: 'forks'`, `isolate: true`), and the prefix must be set before any `src/` module is imported.
- **Each prefix still needs its initial state**, so seeds have to be restored under a new prefix:
  - ES: snapshot restore with `rename_pattern` / `rename_replacement`.
  - Redis: keys and streams copied to the new namespace.
  - MinIO: objects copied into the file's bucket.
  - Restoring must be much faster than the 40–50 s of init.
- **ES has a shard ceiling.** One prefix is 14 indices / 28 shards, and ES allows 1000 shards per node by default, so at most ~35 prefixes can exist at once. Each file must delete its prefix at the end, and a sweeper must clean up after crashed runs.
- **State outside the prefix breaks isolation silently.** It needs an audit: locks, connector queues and exchanges, anything named without the prefix, cluster-wide ES settings.

## Where testcontainers is worth it

Testcontainers pays off when a test needs control over a backend instance (its version, topology, lifecycle or cluster-wide state), or a cheap external service. A test that only needs a clean namespace in a standard backend should use a prefix.

1. **Same tests against other backends and topologies.** The engine supports Elasticsearch and OpenSearch (`src/database/engine.ts`), and Redis can run standalone, as a cluster or with Sentinel (`src/database/redis.ts`). CI only tests ES 8 with a single Redis.
2. **Migration tests.** Start a container seeded with data from release N-1, boot the current code, and check the migrations (163 in `src/migrations`). This can't run on a shared cluster, because migrations change templates and mappings and reindex.
3. **Failure and resilience tests.** Stop, pause or restart a backend in the middle of a test, or add latency and cuts with Toxiproxy: Redis restarts, lock behaviour, RabbitMQ reconnects, ES timeouts.
4. **Cluster-wide or destructive operations.** Template upgrades, ILM, cluster settings, shard limits, deleting all indices.
5. **Short-lived external services**, which start in 1–3 s and can be per test:
   - an HTTP mock server for ingestion feeds (TAXII, RSS, CSV, JSON), including redirect and SSRF cases;
   - Keycloak or OpenLDAP for authentication providers;
   - an SMTP catcher;
   - a forward proxy.
6. **Developer experience.** `yarn test` on a fresh clone with only Docker, random ports so worktrees and CI jobs don't collide, and automatic cleanup through Ryuk, even after a crash.
7. **Other OpenCTI processes.** The remote platforms that `11-sync` needs, or the worker image, started by the test instead of the CI compose file.

The two candidates to try first are a migration test on data seeded from an older version (needs a cluster of its own) and an ingestion-feed test against an HTTP mock container (cheap, and a service the platform doesn't have today).

## Practical findings

- **Dependencies.** `testcontainers` and `@testcontainers/{elasticsearch,redis,rabbitmq,minio}` are pinned at 12.2.0. The modules declare `testcontainers: ^12.2.0`, so yarn installed nested 12.2.1 copies. That broke typing (`RedisContainer` was not assignable to `GenericContainer`), so `package.json` pins `testcontainers` to 12.2.0 in `resolutions`. The `ssh2` and `cpu-features` build scripts are disabled by our yarn policy, which is harmless: they're only needed for SSH Docker hosts.
- **Rootless Podman (macOS).** Ryuk fails with `new reaper: ping: permission denied ... docker.sock`. `TESTCONTAINERS_RYUK_PRIVILEGED=true` fixes it, and no containers were left behind after the runs. Docker on CI is not affected.
- **ES module defaults.** `@testcontainers/elasticsearch` turns on security (basic auth through `ELASTIC_PASSWORD`) and forces `-Xmx2G`. CI runs ES with `xpack.security.enabled=false`, so ES should be configured with a `GenericContainer` matching CI, as the measurement script does.
- **CI runs the tests inside a container** (`filigran/builder` via `docker run`). Testcontainers there needs the Docker socket mounted, or the tests must run on the runner directly.

## Not done

- **Measuring through testcontainers on a CI runner.** `.github/workflows/poc-testcontainers-measure.yml` runs the script on a GitHub runner when `poc-testcontainers` is pushed, but it hasn't run yet. A "3 stacks started at once" case should be added to measure CPU contention on the runner.
- **Phases 1 to 5 of the revised plan:**
  1. one prefix per file on the existing backends;
  2. seeds restored under a prefix;
  3. managers and HTTP declared per file;
  4. testcontainers evaluated as the provisioning layer;
  5. measure and decide.

## Reproduce

```bash
cd opencti-platform/opencti-graphql
# Add TESTCONTAINERS_RYUK_PRIVILEGED=true on rootless Podman
node script/poc-testcontainers-measure.ts 3 > measure.json
```

The JSON report goes to stdout and progress to stderr.

# OpenCTI development environment (v2, mise)

One development container carrying every toolchain, talking to the
infrastructure containers next to it — and the exact same commands available
natively for anyone who would rather not develop inside Docker.

`mise.toml`, at the repository root, is the single source of truth: it pins the
runtime versions and declares the tasks. The container, the host and CI all read
that one file, so no step can exist in only one of the three.

> The historical `.devcontainer/` is still there and still works. This directory
> does not replace it yet; pick one, don't mix them.

---

## Before anything else: give Docker enough memory

Memory is the binding constraint here, not CPU. Elasticsearch alone reserves
around 2.7 GB, Vite around 1.2, the backend more than a gigabyte once it is
serving, and a JetBrains backend adds two `js-language-service` processes of
roughly 1.3 GB each. With 16 GB allocated to Docker Desktop, running
`mise run seed` — which performs a full esbuild build of its own — reliably
triggered OOM kills.

**Give Docker Desktop 24 GB if the machine can spare it.** A platform that dies
halfway through a boot with no error in its own logs is almost always this.

---

## Mode 1 — the dev container

### Prerequisites

Docker (or Podman), and one of:

- **VS Code** with the Dev Containers extension → *Reopen in Container*, then
  pick **OpenCTI (mise)** — the legacy `.devcontainer/` is offered alongside it
- **JetBrains** (IDEA, WebStorm, PyCharm) → *Remote Development* ▸ *Dev
  Containers* ▸ *Create and Mount* on `.devcontainer/v2/devcontainer.json`
- **the `devcontainer` CLI**, no editor at all:

  ```bash
  devcontainer up --workspace-folder . \
    --config .devcontainer/v2/devcontainer.json
  ```

  The `--config` is not optional: without it the CLI picks
  `.devcontainer/devcontainer.json`, the historical one.

Nothing essential lives in `customizations`, so all three behave the same.

### What happens on the first start

`postCreateCommand` runs [`post-create.sh`](post-create.sh), which is idempotent
from end to end:

1. repairs the ownership of the named-volume mount points (a safety net — the
   image already creates them with the right owner);
2. `mise install` — Node and Python exactly as pinned, plus the `.venv`;
3. `corepack enable` + `mise reshim` — Yarn, from the `packageManager` field;
4. `mise run setup` — dependencies of the four applications, and
   `config/development.json` if it is missing;
5. `post-start.sh` — starts the API and the frontend.

Count roughly ten to fifteen minutes; the native modules (`re2`,
`node-calls-python`) are compiled during step 4.

Every **later** start goes through the workspace container's own `command:`,
which runs [`post-start.sh`](post-start.sh) before sleeping. That is deliberate:
`postStartCommand` is the specified hook for it, but JetBrains never runs it, so
using it would quietly make auto-start a VS Code-only feature.

### Once it is up

| | |
|---|---|
| Frontend | <http://localhost:3000> |
| GraphQL API | <http://localhost:4000/graphql> |
| Login | `admin@opencti.io` / `AdminPassword123` |

The API takes a minute or so to build and boot before the UI answers anything
useful.

Ports 3000 and 4000 reach the host through the editor's forwarder
(`forwardPorts`), not through a `ports:` mapping — a mapping would take
127.0.0.1:3000 as soon as the container started, and the forwarder, finding the
port busy, would silently fall back to 3001. The consequence: a workspace
started by hand with `docker compose up` and no editor attached publishes
nothing. Attach an editor, or work from inside the container.

### Logs, and taking the wheel back

The two servers are detached and write to files:

```bash
tail -f /tmp/opencti-back.log
tail -f /tmp/opencti-front.log
```

To run them yourself instead — in an IDE terminal, with the debugger — either
stop them once started, or set `OPENCTI_AUTOSTART=0` in the `environment:` block
of [`docker-compose.yml`](docker-compose.yml) and start them with `mise run dev`.

---

## Mode 2 — on the host, no container

Validated cold on macOS. It needs almost nothing, because
`config/default.json` already targets `localhost` for all five dependencies.

```bash
# 1. the infrastructure, in Docker
docker compose -f opencti-platform/opencti-dev/docker-compose.yml up -d

# 2. the runtimes, from the same mise.toml the container uses
mise trust && mise install

# 3. dependencies and development config
mise run setup

# 4. the API and the frontend, both reloading on a change
mise run dev
```

There is deliberately **no `.env`** and no `.env.example`. Such a file would sit
on the bind mount, visible from the host *and* the container, and mise applies
it over the inherited environment — one developer writing
`ELASTICSEARCH__URL=http://localhost:9200` for their laptop would silently
override the hostnames docker-compose gives the container, and the platform
would fail to boot there with nothing pointing at the culprit. The single value
that differs from the defaults, `SMTP__PORT=1025` (maildev), is identical in
both environments and lives in `mise.toml`.

On macOS, `setup:deps` exports `LIBRARY_PATH` and an `-Wl,-rpath` before
building: under mise, `python3-config --ldflags --embed` names libpython without
ever saying where it is, and `node-calls-python` fails to link with
`ld: library 'python3.12' not found`. That branch is the only OS-specific line
in `mise.toml`; Linux is untouched.

---

## The tasks

Same list everywhere — `mise tasks` prints it.

| Task | What it does |
|---|---|
| `mise run setup` | Provision a fresh checkout (deps + `development.json`) |
| `mise run dev` | API **and** frontend, both reloading on a change |
| `mise run dev:back` | The GraphQL API alone, port 4000 |
| `mise run dev:front` | The frontend alone, port 3000, proxying to the API |
| `mise run dev:worker` | The Python worker (not started by `dev`) |
| `mise run seed` | Load the test dataset into a **running** platform |

A fresh platform holds nothing but its admin user, which makes most of the UI
impossible to look at; `mise run seed` imports the two sample bundles the
repository already ships for its own tests. Run it from a second terminal, once
the platform answers.

Run everything through `mise run` (or from a shell where `mise activate` has
run), and **not** by calling the shims directly: it is the mise environment that
puts `.venv/bin` first, and therefore what makes `pip` install into the virtual
environment rather than into mise's own Python. A child process spawned from a
shim does inherit the right `PATH`, so the backend's Python bridge is fine
either way.

---

## Infrastructure

All of it comes from `opencti-platform/opencti-dev/docker-compose.yml`, which
this stack `include`s rather than copies. The compose project name is pinned to
`opencti-dev` so the named volumes are shared with it — open a plain
`docker compose` there and you get the same Elasticsearch data, not an empty one
replaying a full reindex.

| Service | Host port |
|---|---|
| Elasticsearch | 9200 |
| Kibana | <http://localhost:5601> |
| Redis | 6379 |
| RedisInsight | <http://localhost:5540> |
| RabbitMQ (management) | <http://localhost:15672> |
| MinIO (console) | <http://localhost:9001> |
| maildev (web UI) | <http://localhost:1080> |

The optional profiles — OpenSearch, Keycloak, mokapi, the telemetry stack — are
still available on demand from that file; see its own README. `runServices` in
`devcontainer.json` keeps them out of a normal start.

---

## Troubleshooting

**White page on the first load, `504 Outdated Optimize Dep` on dozens of MUI
chunks.** Vite discovers dependencies while the page loads, re-runs its
pre-bundling, and the requests already in flight die. Clear the cache and
restart the frontend:

```bash
rm -rf opencti-platform/opencti-front/node_modules/.vite
```

The durable remedy would be an `optimizeDeps.include` list in `vite.config.ts`.
Not done yet — that is application configuration, and this environment has so
far stayed out of it.

**The backend stopped and nothing restarted it.** `watchexec` restarts
`dev:back` on a *file change*, never on a crash: the process dies, the watcher
stays up watching nothing. Save a file, or restart the task. A real supervisor
is the open item here.

**`yarn: command not found` after attaching with `docker exec`.** Corepack
writes `yarn` inside mise's Node install, and only `mise reshim` exposes it on
`PATH`. Run `mise reshim`, or just `bash .devcontainer/v2/post-create.sh` —
it is idempotent.

**JetBrains started nine containers you did not ask for.** `runServices` is
declared, but has been observed not being honoured. Stop the extra ones, or
start the stack yourself with
`docker compose -f .devcontainer/v2/docker-compose.yml up -d workspace` before
attaching.

**`python` or `pip` behaving as if the venv did not exist.** Calling the shim
directly resolves to mise's own Python. Use `mise run`, `mise exec`, or a shell
where `mise activate` has run.

---

## Editing these files

- `mise.toml` is shared by the container, the host and CI. Anything true in only
  one of them does not belong there — the container's specifics go in
  `post-start.sh`, which is the only file that concerns it alone.
- Everything under this directory carries its rationale in comments. If a line
  looks redundant, read the comment above it before removing it; most of them
  are there because the obvious version failed on one of the three clients.

"""The OpenCTI lab: OpenCTI's backend AND front built from this checkout, seeded, every page signed in.

``[service.lab]`` in ``.xtm-one/checks.toml`` runs this script (standard library only, helpers in ``lab.py``) in an
XTM One sandbox (``sandbox_start_service``), so an agent can render an OpenCTI pull request before its review.
Ported from XTM-One-Platform/xtm-one ``.xtm-one/lab/opencti_pr_head.py``; here the checkout IS the OpenCTI source:

1. The source is this repository's checkout at the PR head (``LAB_OPENCTI_CHECKOUT`` names a sub-directory instead).
   A partial checkout needs SUB_PATHS.
2. Node and yarn are pinned downloads (``lab.NODE``, ``lab.YARN``); ``yarn workspaces focus`` installs the GraphQL
   and front workspaces; the backend's Python requirements (STIX pattern checks) are pip-installed.
3. The backend: the connectors manifest (fetched, else an empty catalog is written), ``graphql-codegen``, the esbuild
   development build, then ``build/back.mjs`` on ``BACKEND_PORT`` against the lab's OpenSearch, RabbitMQ, Redis and S3
   services (``lab-search``, ``lab-broker``, ``lab-redis``, ``lab-s3``) under their own prefixes. Migrations run at
   its boot.
4. The front: ``relay-compiler`` on the checkout's schema, then Vite on ``VITE_PORT`` proxied to that backend.
5. This script listens on ``PORT``, the preview port: every request goes to Vite with the lab admin's bearer token,
   so every page renders signed in (no sign-in form). ``/lab/theme/dark`` and ``/lab/theme/light`` set the admin's
   theme and redirect to the page named by ``?next=`` (default the dashboard).
6. Seed (``SEED``): one label, one vocabulary entry, then one FILLED and one EMPTY entity per main type
   (Organization, Individual, Sector, System, Report, Indicator, Malware). Each page is logged
   ``seeded opencti page <label>: <url>`` (the service's ``session_log``: the start answer lists them).
   A PR adds its own seed in ``opencti-lab-seed.json`` at the checkout's root (``LAB_OPENCTI_SEED`` names
   another file): ``[{"label": ..., "query": "mutation ...", "variables": {...}, "path": "/dashboard/.../{id}"}]``,
   ``{id}`` being the ``id`` of the mutation's first field.
"""

from __future__ import annotations

import base64
import http.client
import http.server
import io
import json
import os
import secrets
import select
import socket
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab  # noqa: E402 - .xtm-one/lab/lab.py beside this file: the pinned toolchain and the process helpers

PORT = 3500
VITE_PORT = 3501
BACKEND_PORT = 4100
BACKEND_URL = f"http://127.0.0.1:{BACKEND_PORT}"
HEALTH_KEY = "lab-only-opencti-pr-head-health"
HEALTH_URL = f"{BACKEND_URL}/health?health_access_key={HEALTH_KEY}"
ADMIN_EMAIL = "lab@filigran.io"
ADMIN_PASSWORD = "lab-only-password"
#: The lab admin's API token: the proxy sends it on every request.
ADMIN_TOKEN = "00000000-0000-4000-8000-000000000002"
#: The prefix this lab's stores carry.
PREFIX = "lab"
SESSION_PREFIX = "seeded opencti page"
SEED_ENV = "LAB_OPENCTI_SEED"
SEED_FILE = "opencti-lab-seed.json"
GRAPHQL_DIR = "opencti-platform/opencti-graphql"
FRONT_DIR = "opencti-platform/opencti-front"
#: What the nested OpenCTI checkout must hold: both workspaces, their siblings' manifests and the lock.
SUB_PATHS = (
    "package.json",
    "yarn.lock",
    ".yarnrc.yml",
    "patch",
    "opencti-platform/opencti-front",
    "opencti-platform/opencti-graphql",
    "opencti-platform/eslint-plugin-custom-rules",
)
THEMES = ("dark", "light")
#: Answered by this script once the backend is healthy (the preview server starts after it).
READY_PATH = "/lab/ready"


def backend_env(encryption_key: str) -> dict[str, str]:
    """The environment of the lab's backend: the lab's stores under this lab's own prefixes."""
    return {
        "NODE_ENV": "development",
        "NODE_OPTIONS": "--max-old-space-size=4096",
        "APP__PORT": str(BACKEND_PORT),
        "APP__BASE_URL": f"http://localhost:{PORT}",
        "APP__HEALTH_ACCESS_KEY": HEALTH_KEY,
        "APP__ADMIN__EMAIL": ADMIN_EMAIL,
        "APP__ADMIN__PASSWORD": ADMIN_PASSWORD,
        "APP__ADMIN__TOKEN": ADMIN_TOKEN,
        "APP__ENCRYPTION_KEY": encryption_key,
        "APP__ENABLED_DEV_FEATURES": '["*"]',
        "APP__BOOTSTRAP_WIZARD__ENABLED": "false",
        "APP__TELEMETRY__FILIGRAN__ENABLED": "false",
        "ELASTICSEARCH__URL": "http://localhost:9200",
        "ELASTICSEARCH__INDEX_PREFIX": PREFIX,
        "RABBITMQ__HOSTNAME": "localhost",
        "RABBITMQ__PORT": "5672",
        "RABBITMQ__USERNAME": "guest",
        "RABBITMQ__PASSWORD": "guest",
        "RABBITMQ__QUEUE_PREFIX": PREFIX,
        "REDIS__HOSTNAME": "localhost",
        "REDIS__PORT": "6380",
        "REDIS__NAMESPACE": PREFIX,
        "MINIO__ENDPOINT": "localhost",
        "MINIO__PORT": "9002",
        "MINIO__USE_SSL": "false",
        "MINIO__ACCESS_KEY": "opencti",
        "MINIO__SECRET_KEY": "lab-only-opencti-s3",
        "MINIO__BUCKET_NAME": f"{PREFIX}-bucket",
    }


# --- Seed -----------------------------------------------------------------------------------------------------------

LABEL = {"value": "lab-seeded", "color": "#0fbcff"}
VOCABULARY = {"name": "lab-vocabulary-entry", "category": "report_types_ov", "description": "Seeded by the OpenCTI lab"}
FILLED_DESCRIPTION = (
    "Seeded by the OpenCTI lab. This description is long enough to wrap on a wide screen, so the "
    "overview's text block, its truncation and its expand control render as they would with real data."
)
INDICATOR_PATTERN = "[ipv4-addr:value = '198.51.100.7']"

#: (label, mutation field, input type, route of its page, filled input, empty input). Order matters: the report
#: links the filled organization and malware seeded before it.
TYPES: tuple[tuple[str, str, str, str, dict, dict], ...] = (
    ("Organization", "organizationAdd", "OrganizationAddInput", "/dashboard/entities/organizations/{id}",
     {"description": FILLED_DESCRIPTION, "x_opencti_organization_type": "vendor", "x_opencti_score": 80}, {}),
    ("Individual", "individualAdd", "IndividualAddInput", "/dashboard/entities/individuals/{id}",
     {"description": FILLED_DESCRIPTION}, {}),
    ("Sector", "sectorAdd", "SectorAddInput", "/dashboard/entities/sectors/{id}",
     {"description": FILLED_DESCRIPTION}, {}),
    ("System", "systemAdd", "SystemAddInput", "/dashboard/entities/systems/{id}",
     {"description": FILLED_DESCRIPTION}, {}),
    ("Malware", "malwareAdd", "MalwareAddInput", "/dashboard/arsenal/malwares/{id}",
     {"description": FILLED_DESCRIPTION, "malware_types": ["ransomware"], "is_family": True,
      "aliases": ["LabLocker", "LL-26"]}, {}),
    ("Indicator", "indicatorAdd", "IndicatorAddInput", "/dashboard/observations/indicators/{id}",
     {"description": FILLED_DESCRIPTION, "pattern_type": "stix", "pattern": INDICATOR_PATTERN,
      "x_opencti_main_observable_type": "IPv4-Addr", "x_opencti_score": 75, "indicator_types": ["malicious-activity"],
      "valid_from": "2026-11-01T00:00:00.000Z"},
     {"pattern_type": "stix", "pattern": "[domain-name:value = 'empty.lab.example']",
      "x_opencti_main_observable_type": "Domain-Name"}),
    ("Report", "reportAdd", "ReportAddInput", "/dashboard/analyses/reports/{id}",
     {"description": FILLED_DESCRIPTION, "report_types": ["threat-report"], "published": "2026-11-10T09:00:00.000Z",
      "confidence": 80},
     {"published": "2026-11-10T09:00:00.000Z"}),
)


def mutation(field: str, input_type: str) -> str:
    return f"mutation LabSeed($input: {input_type}!) {{ {field}(input: $input) {{ id }} }}"


def seed_plan(label_id: str | None) -> list[dict]:
    """The seed of every main type, filled then empty: ``{label, query, variables, path, kind}`` each.

    The filled entities carry the seeded label; the filled report contains the filled organization and malware
    (``objects`` is filled in by :func:`run_seed` once their ids are known: ``kind`` names them).
    """
    plan: list[dict] = []
    for label, field, input_type, path, filled, empty in TYPES:
        for state, extra in (("filled", filled), ("empty", empty)):
            data = {"name": f"Lab {label} ({state})", **extra}
            if state == "filled" and label_id:
                data["objectLabel"] = [label_id]
            plan.append({"label": f"{label} {state}", "query": mutation(field, input_type), "variables": {"input": data},
                         "path": path, "kind": f"{label.lower()}-{state}"})
    return plan


def extra_seed(checkout: Path, environ: dict[str, str] | None = None) -> list[dict]:
    """The PR's own seed (``opencti-lab-seed.json`` or ``LAB_OPENCTI_SEED``); a malformed file stops the start."""
    environ = os.environ if environ is None else environ
    path = checkout / environ.get(SEED_ENV, SEED_FILE)
    if not path.is_file():
        return []
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise SystemExit(f"opencti-lab: {path.name} is not JSON: {exc}") from None
    if not isinstance(entries, list) or not all(
        isinstance(e, dict) and isinstance(e.get("label"), str) and isinstance(e.get("query"), str) for e in entries
    ):
        raise SystemExit(f"opencti-lab: {path.name} must be a list of {{label, query, variables?, path?}} objects")
    return [{"label": e["label"], "query": e["query"], "variables": e.get("variables") or {}, "path": e.get("path") or "",
             "kind": "extra"} for e in entries]


def created_id(answer: dict) -> str:
    """The ``id`` of the first field of a mutation's answer, empty on an error."""
    data = answer.get("data") if isinstance(answer, dict) else None
    if not isinstance(data, dict) or answer.get("errors"):
        return ""
    first = next(iter(data.values()), None)
    return str(first.get("id") or "") if isinstance(first, dict) else ""


def page_url(base: str, path: str, entity_id: str) -> str:
    return f"{base}{path.replace('{id}', entity_id)}" if path and entity_id else ""


# --- GraphQL --------------------------------------------------------------------------------------------------------


def graphql(query: str, variables: dict | None = None) -> dict:
    """*query* on the lab's backend as the lab admin."""
    request = urllib.request.Request(
        f"{BACKEND_URL}/graphql",
        data=json.dumps({"query": query, "variables": variables or {}}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return {"errors": [{"message": f"HTTP {exc.code}: {exc.read()[:300].decode('utf-8', 'replace')}"}]}


def run_seed(plan: list[dict], base: str) -> list[tuple[str, str]]:
    """Run *plan*, log each seeded page and return ``(label, url)``; a failed entry is logged and skipped."""
    ids: dict[str, str] = {}
    pages: list[tuple[str, str]] = []
    for entry in plan:
        variables = json.loads(json.dumps(entry["variables"]))
        if entry["kind"] == "report-filled":
            objects = [ids[k] for k in ("organization-filled", "malware-filled") if ids.get(k)]
            if objects:
                variables["input"]["objects"] = objects
        answer = graphql(entry["query"], variables)
        entity_id = created_id(answer)
        if not entity_id:
            lab.log(f"opencti-lab: seed {entry['label']} failed: {str(answer.get('errors'))[:400]}")
            continue
        ids[entry["kind"]] = entity_id
        url = page_url(base, entry["path"], entity_id)
        if url:
            pages.append((entry["label"], url))
            lab.log(f"{SESSION_PREFIX} {entry['label']}: {url}")
    return pages


def seed_label() -> str:
    answer = graphql("mutation LabLabel($input: LabelAddInput!) { labelAdd(input: $input) { id } }", {"input": LABEL})
    if not created_id(answer):
        lab.log(f"opencti-lab: seed label failed: {str(answer.get('errors'))[:300]}")
    return created_id(answer)


def seed_vocabulary() -> None:
    answer = graphql(
        "mutation LabVocabulary($input: VocabularyAddInput!) { vocabularyAdd(input: $input) { id } }", {"input": VOCABULARY}
    )
    if created_id(answer):
        lab.log(f"opencti-lab: seeded vocabulary {VOCABULARY['category']}: {VOCABULARY['name']}")
    else:
        lab.log(f"opencti-lab: seed vocabulary failed: {str(answer.get('errors'))[:300]}")


#: The names OpenCTI reads as each theme (utils/themeName.ts of the front: built-in first, then legacy).
THEME_NAMES = {"dark": ("Filigran Dark", "Dark"), "light": ("Filigran Light", "Light")}


def theme_value(theme: str, answer: dict) -> str:
    """The value of the user's ``theme`` field for *theme*, from a ``themes`` query *answer*.

    Since the theme module, ``me.theme`` is a theme id (the front falls back to the platform theme on any other
    value); an older release reads the literal ``dark`` / ``light``, kept when the query answers no match.
    """
    data = answer.get("data") if isinstance(answer, dict) else None
    edges = ((data or {}).get("themes") or {}).get("edges") or []
    by_name = {str(e.get("node", {}).get("name")): str(e.get("node", {}).get("id") or "") for e in edges if isinstance(e, dict)}
    for name in THEME_NAMES[theme]:
        if by_name.get(name):
            return by_name[name]
    return theme


def set_theme(theme: str) -> bool:
    value = theme_value(theme, graphql("query LabThemes { themes(first: 100) { edges { node { id name } } } }"))
    answer = graphql(
        "mutation LabTheme($input: [EditInput]!) { meEdit(input: $input) { id } }",
        {"input": [{"key": "theme", "value": [value]}]},
    )
    return bool(created_id(answer))


# --- Preview --------------------------------------------------------------------------------------------------------


def lab_route(path: str) -> tuple[str, str] | None:
    """``(theme, next path)`` for ``/lab/theme/<dark|light>[?next=...]``, else ``None``.

    ``next`` is kept only as a path of this origin (a full URL or ``//host`` falls back to the dashboard).
    """
    parts = urllib.parse.urlsplit(path)
    if not parts.path.startswith("/lab/theme/"):
        return None
    theme = parts.path.removeprefix("/lab/theme/").strip("/")
    if theme not in THEMES:
        return None
    wanted = urllib.parse.parse_qs(parts.query).get("next", ["/dashboard"])[0]
    if not wanted.startswith("/") or wanted.startswith("//"):
        wanted = "/dashboard"
    return theme, wanted


def forwarded_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    """The request's headers for Vite: the Host rewritten, the admin's bearer token set (no cookie session needed)."""
    kept = {k: v for k, v in headers if k.lower() not in ("host", "connection", "content-length", "authorization")}
    kept["Host"] = f"127.0.0.1:{VITE_PORT}"
    kept["Authorization"] = f"Bearer {ADMIN_TOKEN}"
    return kept


class Preview(http.server.BaseHTTPRequestHandler):
    """The preview port: ``/lab/theme/*`` here, the rest (websockets included) to Vite as the lab admin."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - the base class's name
        return

    def _theme(self, theme: str, wanted: str) -> None:
        done = set_theme(theme)
        lab.log(f"opencti-lab: theme {theme} {'set' if done else 'NOT set'} for the lab admin")
        self.send_response(302)
        self.send_header("Location", wanted)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _tunnel(self) -> None:
        upstream = socket.create_connection(("127.0.0.1", VITE_PORT), timeout=10)
        lines = [f"{self.command} {self.path} {self.request_version}"]
        lines += [f"{k}: {v}" for k, v in forwarded_headers(list(self.headers.items())).items()]
        upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        self.close_connection = True
        sockets = [self.connection, upstream]
        upstream.settimeout(None)
        self.connection.settimeout(None)
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 300)
                if not readable:
                    return
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (upstream if sock is self.connection else self.connection).sendall(data)
        finally:
            upstream.close()

    def _forward(self) -> None:
        if "upgrade" in (self.headers.get("Connection") or "").lower():
            self._tunnel()
            return
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(length) if length else b""
        upstream = http.client.HTTPConnection("127.0.0.1", VITE_PORT, timeout=600)
        headers = forwarded_headers(list(self.headers.items()))
        if payload:
            headers["Content-Length"] = str(len(payload))
        upstream.request(self.command, self.path, body=payload or None, headers=headers)
        response = upstream.getresponse()
        self.send_response(response.status, response.reason)
        for key, value in response.getheaders():
            if key.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(key, value)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        while True:
            chunk = response.read1(65536)
            if not chunk:
                break
            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        upstream.close()

    def _ready(self) -> None:
        data = json.dumps({"ready": True, "backend": BACKEND_URL}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self) -> None:
        try:
            route = lab_route(self.path)
            if self.path.split("?", 1)[0] == READY_PATH:
                self._ready()
            elif route:
                self._theme(*route)
            else:
                self._forward()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle


# --- Start ----------------------------------------------------------------------------------------------------------


def opencti_checkout() -> Path:
    where = lab.CHECKOUT / os.environ.get("LAB_OPENCTI_CHECKOUT", ".")
    if not (where / "yarn.lock").is_file() or not all((where / d / "package.json").is_file() for d in (GRAPHQL_DIR, FRONT_DIR)):
        raise SystemExit(
            f"opencti-lab: no OpenCTI source at {where}: the checkout needs at least {list(SUB_PATHS)}, then start again"
        )
    return where


def connectors_manifest(graphql_dir: Path, node: Path, env: dict[str, str]) -> None:
    """The connectors manifest the catalog imports: fetched as the build does, else an empty catalog (logged)."""
    process = lab.spawn("manifest", [str(node), "script/get-connectors-manifest.ts"], cwd=graphql_dir, env=env, daemon=False)
    if process.wait() == 0:
        return
    target = graphql_dir / "src" / "__generated__" / "opencti-manifest.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"id": "lab-empty-catalog", "name": "Lab empty catalog", "contracts": []}), encoding="utf-8")
    lab.log("opencti-lab: WARNING the connectors manifest could not be fetched: an empty catalog was written")


def toolchain_env(node: Path, environ: dict[str, str]) -> dict[str, str]:
    """The yarn environment: the pinned node first on PATH, and node-gyp pointed at its own headers.

    The pinned node package ships ``include/node``; without ``npm_config_nodedir`` node-gyp downloads the headers
    from nodejs.org, which the sandbox network refuses, and a native module (node-calls-python) fails the install.
    """
    return {**environ, "YARN_ENABLE_TELEMETRY": "0", "YARN_ENABLE_PROGRESS_BARS": "0",
            "YARN_ENABLE_GLOBAL_CACHE": "false", "YARN_CACHE_FOLDER": str(lab.CACHE / "yarn-cache"),
            "npm_config_nodedir": str(node.parent.parent),
            "PATH": f"{node.parent}:{environ.get('PATH', '')}"}


def main() -> None:
    root = opencti_checkout()
    graphql_dir, front = root / GRAPHQL_DIR, root / FRONT_DIR
    lab.ROOT.mkdir(parents=True, exist_ok=True)
    lab.CACHE.mkdir(exist_ok=True)
    node, yarn = lab.CACHE / "node" / "package" / "bin" / "node", lab.CACHE / "yarn" / "package" / "bin" / "yarn.js"
    for spec, target in ((lab.NODE, "node"), (lab.YARN, "yarn")):
        with tarfile.open(fileobj=io.BytesIO(lab.fetch(spec)), mode="r:gz") as archive:
            archive.extractall(lab.CACHE / target, filter="data")
    node.chmod(0o755)
    env = toolchain_env(node, dict(os.environ))
    lab.run("yarn", [str(node), str(yarn), "workspaces", "focus", "opencti-graphql", "opencti-front"], cwd=root, env=env)
    requirements = graphql_dir / "src" / "python" / "requirements.txt"
    if requirements.is_file():
        pip = lab.spawn("pip", [sys.executable, "-m", "pip", "install", "-q", "-r", str(requirements)], daemon=False)
        if pip.wait() != 0:
            lab.log("opencti-lab: WARNING the backend's Python requirements did not install: STIX pattern checks fail")
    connectors_manifest(graphql_dir, node, env)
    lab.run("codegen", [str(node), str(yarn), "build:types"], cwd=graphql_dir, env=env)
    lab.run("backend-build", [str(node), "builder/builder.ts", "--development"], cwd=graphql_dir, env=env)
    encryption_key = base64.b64encode(secrets.token_bytes(32)).decode()
    lab.spawn("opencti-backend", [str(node), "--enable-source-maps", "build/back.mjs"], cwd=graphql_dir,
              env={**env, **backend_env(encryption_key)})
    lab.run("relay", [str(node), str(yarn), "relay"], cwd=front, env=env)
    lab.spawn(
        "opencti-front",
        [str(node), "node_modules/vite/bin/vite.js", "--host", "127.0.0.1", "--port", str(VITE_PORT), "--strictPort"],
        cwd=front,
        env={**env, "BACK_END_URL": BACKEND_URL, "FRONT_END_PORT": str(VITE_PORT)},
    )
    lab.wait_http(f"http://127.0.0.1:{VITE_PORT}/", 300, "opencti-front")
    lab.wait_http(HEALTH_URL, 1200, "opencti-backend (migrations at boot)")
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Preview)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://localhost:{PORT}"
    seed_vocabulary()
    plan = seed_plan(seed_label()) + extra_seed(lab.CHECKOUT)
    pages = run_seed(plan, base)
    version = json.loads((front / "package.json").read_text(encoding="utf-8")).get("version", "")
    lab.log(f"lab up: {base}/dashboard, OpenCTI {version} backend and front from {root.resolve().name}/, signed in as the lab admin "
            f"on every page; GraphQL at {base}/graphql; {len(pages)} seeded pages; theme: {base}/lab/theme/dark or /lab/theme/light (?next=<path>)")
    while True:
        for child in lab.CHILDREN:
            if child.poll() is not None:
                raise SystemExit(f"opencti-lab: {child.args[0]} exited with {child.returncode}")
        time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    finally:
        for child in lab.CHILDREN:
            if child.poll() is None:
                child.terminate()

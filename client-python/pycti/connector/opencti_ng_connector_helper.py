"""Detached connector helper for **opencti-ng**.

A lightweight drop-in alternative to :class:`OpenCTIConnectorHelper` for
connectors that feed an opencti-ng platform directly, with **no** OpenCTI
registration, RabbitMQ worker, or OpenCTI API:

- It **registers** with opencti-ng (`POST /api/v1/connectors`), **pings**
  (heartbeat) on a background thread, and keeps its run **state server-side**
  (the connectors table) — there is no local state file, so an operator can
  reset a connector's state from the platform and it sticks.
- ``send_stix2_bundle`` POSTs the bundle to ``/api/v1/stix/bundle`` (tagged with
  ``source_type=connector`` + the connector id) and **waits** for the ingestion
  job to complete (sync or async + polling).
- Authentication is a JWT (see the ``connector-jwt`` tool in opencti-ng). The
  connector id is the JWT ``sub`` and the write tenant is its grant, so config
  is just ``url`` + ``jwt``.

It implements exactly the surface external-import connectors use; it is not a
full reimplementation of the legacy helper.
"""

import base64
import binascii
import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import requests

PING_INTERVAL_SECONDS = 40


def _decode_jwt_claims(jwt: str) -> Dict[str, Any]:
    """Decode a JWT payload (middle segment, base64url) — **no** signature check.

    The server verifies the signature on every request; we only read the
    connector id (``sub``) and the write tenant out of the (unverified) payload
    so config can stay just ``url`` + ``jwt``.
    """
    try:
        payload_b64 = jwt.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # pad base64url
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except (IndexError, ValueError, binascii.Error, json.JSONDecodeError) as err:
        raise ValueError(f"opencti-ng jwt is not a valid JWT: {err}") from err


def _jwt_write_tenant(claims: Dict[str, Any]) -> str:
    grants = claims.get("grants") or []
    if grants and grants[0].get("tenant"):
        return grants[0]["tenant"]
    tenants = claims.get("tenants") or []
    if tenants:
        return tenants[0]
    raise ValueError(
        "opencti-ng jwt carries no tenant grant — regenerate it with "
        "`connector-jwt --tenant <uuid>`"
    )


class _ConnectorLogger:
    """Structured-logger shim (`.info/.debug/.warning/.error(msg, meta=...)`)."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    @staticmethod
    def _fmt(message: str, meta: Optional[Dict] = None) -> str:
        # `default=str` so log metadata carrying non-JSON values (e.g. a
        # `timedelta`/`datetime` like a connector's import-start-date) renders
        # instead of raising mid-log and aborting the caller's run.
        return f"{message} {json.dumps(meta, default=str)}" if meta else message

    def debug(self, message: str, meta: Optional[Dict] = None) -> None:
        self._logger.debug(self._fmt(message, meta))

    def info(self, message: str, meta: Optional[Dict] = None) -> None:
        self._logger.info(self._fmt(message, meta))

    def warning(self, message: str, meta: Optional[Dict] = None) -> None:
        self._logger.warning(self._fmt(message, meta))

    def error(self, message: str, meta: Optional[Dict] = None) -> None:
        self._logger.error(self._fmt(message, meta))


class _Metric:
    """No-op metric handler matching the legacy ``helper.metric`` surface."""

    def inc(self, _name: str, _n: int = 1) -> None:
        pass

    def state(self, _state: str) -> None:
        pass


class _WorkApi:
    """Shim for ``helper.api.work`` — work tracking is local/no-op here."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    # All methods accept *args/**kwargs to tolerate the full legacy signatures
    # (e.g. `to_processed(work_id, message, in_error=...)`) — work tracking is a
    # no-op here, so extra arguments are simply ignored.
    def initiate_work(self, _connector_id: str = "", friendly_name: str = "", **_kwargs) -> str:
        work_id = f"work--{uuid.uuid4()}"
        self._logger.info(f"[work] start {work_id}: {friendly_name}")
        return work_id

    def to_processed(self, work_id: str = "", message: str = "", **_kwargs) -> None:
        self._logger.info(f"[work] done {work_id}: {message}")

    def get_connector_works(self, *_args, **_kwargs):
        # No OpenCTI work tracking in detached mode → no outstanding works.
        return []


class _ReadApi:
    """Shim for ``helper.api.<entity>`` GraphQL reads/updates.

    Detached opencti-ng mode has no OpenCTI GraphQL API. Connectors use these
    only for opportunistic lookups (e.g. "does this indicator already exist?
    update its field") — returning empty makes the connector fall back to its
    normal bundle path, which opencti-ng upserts (dedup by standard_id). So
    these stubs degrade gracefully rather than crash.
    """

    def __init__(self, logger: logging.Logger, name: str) -> None:
        self._logger = logger
        self._name = name

    def read(self, **_kwargs):
        self._logger.debug(f"[api.{self._name}.read] no-op in opencti-ng mode")
        return None

    def list(self, **_kwargs):
        self._logger.debug(f"[api.{self._name}.list] no-op in opencti-ng mode")
        return []

    def update_field(self, **_kwargs):
        self._logger.debug(f"[api.{self._name}.update_field] no-op in opencti-ng mode")
        return None


class _Api:
    def __init__(self, logger: logging.Logger) -> None:
        self.work = _WorkApi(logger)
        # Entity read/update shims used by some connectors (e.g. CrowdStrike's
        # YARA/Snort importers and report malware-guessing). No-ops here.
        self.indicator = _ReadApi(logger, "indicator")
        self.malware = _ReadApi(logger, "malware")
        self.stix_domain_object = _ReadApi(logger, "stix_domain_object")


class OpenCTINGConnectorHelper:
    """Detached helper that ingests directly into opencti-ng."""

    def __init__(self, config: Dict[str, Any]) -> None:
        ng = config.get("opencti-ng") or config.get("opencti_ng")
        if not ng:
            raise ValueError("missing 'opencti-ng' configuration section")

        self.base_url = str(ng["url"]).rstrip("/")
        self.jwt = ng["jwt"]
        claims = _decode_jwt_claims(self.jwt)
        self.tenant = _jwt_write_tenant(claims)
        # The connector id IS the JWT subject (stable uuid5(name)).
        self.connector_id = claims.get("sub")
        if not self.connector_id:
            raise ValueError("opencti-ng jwt has no 'sub' (connector id)")
        self.connect_id = self.connector_id

        connector = config.get("connector") or {}
        self.connector_name = connector.get("name", "connector")
        # Legacy-helper alias used by connectors (e.g. CrowdStrike) for log lines
        # and work friendly-names.
        self.connect_name = self.connector_name
        self.connector_type = connector.get("type", "EXTERNAL_IMPORT")
        scope = connector.get("scope")
        self.connect_scope = scope if isinstance(scope, list) else None
        # Some connectors read a default confidence off the helper.
        self.connect_confidence_level = int(connector.get("confidence_level", 100))
        self._run_and_terminate = bool(connector.get("run_and_terminate", False))
        # Interval for `schedule_iso` (seconds); also accepted as a kwarg there.
        self._duration_period = connector.get("duration_period")

        # Client-side retry of objects that failed with a *transient* server
        # error (e.g. a TiDB PD/TiKV failover blip, or a dedup/identifier race).
        # Only the affected objects are re-submitted, with exponential backoff.
        self._ingest_max_retries = int(ng.get("ingest_max_retries", 3))
        self._ingest_retry_backoff = float(ng.get("ingest_retry_backoff", 2.0))

        # State lives on the server (connectors table). This is just an in-memory
        # mirror, seeded at register and synced via ping; guarded by a lock
        # because the ping thread and set_state both touch it. There is no local
        # state file — state is server-authoritative so an operator "reset state"
        # actually sticks (a local cache would re-seed stale state on restart).
        self._server_state: Optional[Dict] = None
        self._state_lock = threading.Lock()

        # Logging
        level = str(connector.get("log_level", "info")).upper()
        logging.basicConfig(level=getattr(logging, level, logging.INFO))
        self._logger = logging.getLogger("opencti-ng-connector")
        self._logger.setLevel(getattr(logging, level, logging.INFO))
        self.connector_logger = _ConnectorLogger(self._logger)
        self.metric = _Metric()
        self.api = _Api(self._logger)

        # HTTP session — every request carries the JWT + tenant context.
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self.jwt}",
                "X-OpenCTI-Tenant-Write": self.tenant,
                "X-OpenCTI-Tenant-Read": self.tenant,
                "Content-Type": "application/json",
            }
        )

        self.log_info(
            f"opencti-ng helper ready (url={self.base_url}, tenant={self.tenant}, "
            f"connector={self.connector_id})"
        )

        # Register on startup and seed state from the server; then start the
        # heartbeat. Best-effort: if the platform is briefly unreachable we start
        # with no state and keep retrying via the ping thread.
        self._register()
        self._stop = threading.Event()
        self._ping_thread = threading.Thread(
            target=self._ping_loop, name="opencti-ng-ping", daemon=True
        )
        self._ping_thread.start()

    # ── logging ─────────────────────────────────────────────────────────
    def log_debug(self, message: str) -> None:
        self._logger.debug(message)

    def log_info(self, message: str) -> None:
        self._logger.info(message)

    def log_warning(self, message: str) -> None:
        self._logger.warning(message)

    def log_error(self, message: str) -> None:
        self._logger.error(message)

    # ── lifecycle: register + ping ───────────────────────────────────────
    def get_run_and_terminate(self) -> bool:
        return self._run_and_terminate

    @staticmethod
    def _duration_to_seconds(duration: Any) -> int:
        """Coerce a schedule period to whole seconds.

        Accepts a ``datetime.timedelta``, a number of seconds, or an ISO-8601
        duration string (``PT30M``/``P1D``). Falls back to a best-effort parse;
        unknown/zero means "run once".
        """
        import datetime as _dt
        import re

        if duration is None:
            return 0
        if isinstance(duration, _dt.timedelta):
            return int(duration.total_seconds())
        if isinstance(duration, (int, float)):
            return int(duration)
        s = str(duration).strip()
        if s.isdigit():
            return int(s)
        # Minimal ISO-8601 duration parse (days/hours/minutes/seconds).
        m = re.fullmatch(
            r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", s, re.IGNORECASE
        )
        if m:
            d, h, mi, sec = (int(x) if x else 0 for x in m.groups())
            return d * 86400 + h * 3600 + mi * 60 + sec
        return 0

    def schedule_iso(
        self, message_callback, duration_period=None
    ) -> None:
        """Run ``message_callback`` immediately, then every ``duration_period``.

        Mirrors the legacy helper's surface so connectors that schedule via the
        helper work unchanged. ``duration_period`` may be a ``timedelta``, ISO-8601
        duration string, or seconds; defaults to the connector config value. If
        ``run_and_terminate`` is set, runs once and returns.
        """
        period = self._duration_to_seconds(
            duration_period if duration_period is not None else self._duration_period
        )
        self.log_info(f"scheduling connector run every {period}s")
        while True:
            try:
                message_callback()
            except (KeyboardInterrupt, SystemExit):
                self.log_info("connector stop requested")
                self.stop()
                return
            except Exception as err:  # keep the loop alive on a run error
                self.log_error(f"connector run error: {err}")
            if self._run_and_terminate or period <= 0:
                return
            time.sleep(period)

    def stop(self) -> None:
        """Stop the heartbeat thread (best-effort)."""
        stop_evt = getattr(self, "_stop", None)
        if stop_evt is not None:
            stop_evt.set()

    def _register(self) -> None:
        """Register/upsert this connector and seed state from the server."""
        try:
            resp = self._session.post(
                f"{self.base_url}/api/v1/connectors",
                data=json.dumps(
                    {
                        "name": self.connector_name,
                        "type": self.connector_type,
                        "scope": self.connect_scope,
                    }
                ),
                timeout=30,
            )
            if resp.status_code != 200:
                self.log_warning(
                    f"connector register failed: HTTP {resp.status_code} {resp.text[:300]}"
                )
                return
            state = resp.json().get("connector_state")
            with self._state_lock:
                self._server_state = state if isinstance(state, dict) else None
            self.log_info("connector registered with opencti-ng")
        except requests.RequestException as err:
            self.log_warning(f"connector register error (state unavailable): {err}")

    def _send_ping(self, state: Optional[Dict]) -> None:
        """POST one ping and adopt the server's authoritative state.

        `state=None` is a pure heartbeat: it must NOT re-push the connector's
        cached state, otherwise an operator "reset state" (which nulls the server
        value) would be clobbered on the next ping (the server upserts state with
        COALESCE, so a non-null push wins). `set_state` passes the new state to
        persist it. Either way we adopt whatever the server returns, so a reset
        propagates back to this process.
        """
        info = {"run_and_terminate": self._run_and_terminate}
        try:
            resp = self._session.post(
                f"{self.base_url}/api/v1/connectors/{self.connector_id}/ping",
                data=json.dumps({"state": state, "info": info}),
                timeout=30,
            )
            if resp.status_code != 200:
                self.log_warning(f"ping failed: HTTP {resp.status_code} {resp.text[:200]}")
                return
            remote = resp.json().get("connector_state")
            with self._state_lock:
                self._server_state = remote if isinstance(remote, dict) else None
        except requests.RequestException as err:
            self.log_warning(f"ping error: {err}")

    def _ping(self) -> None:
        """Heartbeat only — never pushes cached state (see `_send_ping`)."""
        self._send_ping(None)

    def _ping_loop(self) -> None:
        while not self._stop.wait(PING_INTERVAL_SECONDS):
            self._ping()

    def force_ping(self) -> None:
        self._ping()

    # ── state: server-side blob (no local file) ──────────────────────────
    def get_state(self) -> Optional[Dict]:
        with self._state_lock:
            return self._server_state

    def set_state(self, state: Dict) -> None:
        with self._state_lock:
            self._server_state = state
        # Persist immediately to the server (the only store — no local cache).
        self._send_ping(state)
        self.log_debug(f"state set: {state}")

    # ── ingestion ───────────────────────────────────────────────────────
    @staticmethod
    def _to_stix_dict(item):
        """Normalise one bundle item to a plain JSON-able dict.

        Handles native stix2 library objects (`.serialize()`), connectors-sdk
        models (`.to_stix2_object()` → stix2 object), and already-plain dicts.
        """
        if hasattr(item, "serialize"):
            return json.loads(item.serialize())
        if hasattr(item, "to_stix2_object"):
            return json.loads(item.to_stix2_object().serialize())
        return item

    @classmethod
    def stix2_create_bundle(cls, items) -> Optional[str]:
        """Wrap a list of STIX 2.1 objects into a bundle JSON string.

        Accepts native stix2 objects, connectors-sdk models, plain dicts, and
        (possibly nested) lists of these — mappers sometimes return a list of
        relationships per item. Returns ``None`` for an empty input. The final
        `default=str` is a safety net so a stray non-JSON value (e.g. a stray
        `timedelta`/`datetime` in a dict) degrades to a string instead of
        raising during ingestion.
        """
        if not items:
            return None

        objects: list = []

        def _add(obj):
            if obj is None:
                return
            if isinstance(obj, (list, tuple)):
                for sub in obj:
                    _add(sub)
            else:
                objects.append(cls._to_stix_dict(obj))

        _add(items)

        if not objects:
            return None
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }
        return json.dumps(bundle, default=str)

    # Error types whose objects are worth re-submitting unconditionally: a clean
    # re-send succeeds once the transient/race condition clears.
    # `validation`/`internal` are never retried (bad data / real bugs).
    _RETRYABLE_ERROR_TYPES = {"database_transient", "conflict"}

    def send_stix2_bundle(self, bundle: str, **kwargs) -> List[str]:
        """POST a STIX2 bundle to opencti-ng and wait for ingestion to finish.

        Objects that fail with a *transient* server error (a TiDB PD/TiKV
        failover blip, a dedup/identifier race) are re-submitted on their own,
        with exponential backoff, up to ``ingest_max_retries`` times. Ingestion
        is idempotent (dedup by ``standard_id``), so re-sending is safe.

        Returns the list of ingestion ids (one per attempt). Raises on a failed
        ingestion or HTTP error. Unknown kwargs (work_id, update, …) are accepted
        for legacy-helper compatibility and ignored.
        """
        try:
            bundle_obj = json.loads(bundle)
        except json.JSONDecodeError as err:
            raise ValueError(f"send_stix2_bundle: invalid bundle JSON: {err}") from err

        # Index by STIX id so retryable error ids map back to the source object.
        objects_by_id = {
            obj["id"]: obj
            for obj in bundle_obj.get("objects", [])
            if isinstance(obj, dict) and "id" in obj
        }

        ingestion_ids: List[str] = []
        result = self._submit_and_wait(bundle_obj, kwargs.get("ingest_ids"))
        ingestion_ids.append(result.get("ingestion_id", ""))
        self._report_result(result.get("ingestion_id", ""), result)

        retry_objects = self._collect_retryable_objects(result, objects_by_id)
        attempt = 0
        while retry_objects and attempt < self._ingest_max_retries:
            attempt += 1
            delay = self._ingest_retry_backoff * (2 ** (attempt - 1))
            self.log_warning(
                f"retrying {len(retry_objects)} object(s) after transient errors "
                f"in {delay:.0f}s (attempt {attempt}/{self._ingest_max_retries})"
            )
            time.sleep(delay)
            sub_bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.1",
                "objects": retry_objects,
            }
            result = self._submit_and_wait(sub_bundle, None)
            ingestion_ids.append(result.get("ingestion_id", ""))
            self._report_result(result.get("ingestion_id", ""), result)
            retry_objects = self._collect_retryable_objects(result, objects_by_id)

        if retry_objects:
            still = [obj.get("id") for obj in retry_objects]
            self.log_error(
                f"{len(retry_objects)} object(s) still failing with transient errors "
                f"after {self._ingest_max_retries} retries: {still[:20]}"
            )
        return ingestion_ids

    def _submit_and_wait(
        self, bundle_obj: Dict[str, Any], ingest_ids: Optional[List[str]]
    ) -> Dict[str, Any]:
        """POST one bundle (forced async) and return the completed job result."""
        payload: Dict[str, Any] = {
            "bundle": bundle_obj,
            # Provenance: this ingestion is driven by this connector instance.
            "source_type": "connector",
            "source_id": self.connector_id,
        }
        if ingest_ids:
            payload["ingest_ids"] = ingest_ids

        n_objects = len(bundle_obj.get("objects", []))
        self.log_info(f"sending bundle ({n_objects} objects) to opencti-ng…")

        resp = self._session.post(
            f"{self.base_url}/api/v1/stix/bundle",
            data=json.dumps(payload, default=str),
            headers={"X-Async": "true"},
            timeout=120,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"opencti-ng ingestion POST failed: HTTP {resp.status_code} {resp.text[:500]}"
            )
        body = resp.json()
        status = body.get("status")
        if status == "completed":
            return body
        if status != "processing":
            raise RuntimeError(f"unexpected ingestion status '{status}': {body}")
        # Async — poll the job to completion.
        return self._poll_until_done(body.get("ingestion_id", ""))

    def _collect_retryable_objects(
        self, result: Dict[str, Any], objects_by_id: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Map a result's retryable error ids back to their source objects.

        Server error ids are formatted ``"{stix_id}/{type}"``; the source object
        is looked up by the ``stix_id`` part. Deduplicated; order doesn't matter
        (the server topo-sorts each bundle).

        Two kinds of group are collected:

        * ``database_transient`` / ``conflict`` — the object itself hit a transient
          server condition; a clean re-send succeeds once it clears.
        * ``dependency`` — the object failed only because a *referent* failed. This
          is collateral damage from a transient failure elsewhere (e.g. the
          referenced vulnerability hit a pool timeout). It is worth resubmitting
          **only when that referent is itself in this bundle** (``dependency_id``
          present in ``objects_by_id``): the referent is then also collected here,
          so the retry sub-bundle carries both and the server ingests the referent
          first, then resolves the dependent. A genuinely dangling reference
          (referent in no bundle) is skipped — resending can never satisfy it.
        """
        out: Dict[str, Any] = {}

        def collect_ids(group: Dict[str, Any]) -> None:
            for err_id in group.get("ids") or []:
                stix_id = err_id.rsplit("/", 1)[0]
                obj = objects_by_id.get(stix_id)
                if obj is not None:
                    out[stix_id] = obj

        for group in result.get("errors") or []:
            etype = group.get("error_type")
            if etype in self._RETRYABLE_ERROR_TYPES:
                collect_ids(group)
            elif etype == "dependency":
                dep_id = group.get("dependency_id")
                if dep_id is not None and dep_id in objects_by_id:
                    collect_ids(group)
        return list(out.values())

    def _poll_until_done(self, ingestion_id: str) -> Dict[str, Any]:
        job_uuid = ingestion_id.replace("ingestion--", "")
        url = f"{self.base_url}/api/v1/ingestions/{job_uuid}"
        # The endpoint long-polls up to `timeout` seconds per call; loop until
        # the job leaves "processing".
        while True:
            resp = self._session.get(url, params={"timeout": 60}, timeout=120)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"opencti-ng poll failed: HTTP {resp.status_code} {resp.text[:500]}"
                )
            body = resp.json()
            status = body.get("status")
            if status == "completed":
                return body
            if status == "failed":
                raise RuntimeError(f"opencti-ng ingestion {ingestion_id} failed: {body}")
            progress = body.get("progress")
            self.log_info(
                f"ingestion {ingestion_id} processing"
                + (f" ({progress}/{body.get('total')})" if progress is not None else "")
            )
            time.sleep(1)

    def _report_result(self, ingestion_id: str, body: Dict[str, Any]) -> None:
        ingested = body.get("ingested")
        errors = body.get("errors") or []
        self.log_info(
            f"ingestion {ingestion_id} completed: ingested={ingested}, "
            f"error_groups={len(errors)}"
        )
        if errors:
            self.log_warning(f"ingestion {ingestion_id} reported errors: {errors}")

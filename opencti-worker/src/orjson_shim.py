# POC ingestion sequencer, study 0011 (work-kb note opencti-worker-gil-profile): the GIL
# profile showed ~34% of wall GIL-held with 28% burnt in JSON tokenization (bundle parsing
# in pycti, payload encoding in requests/simplejson). orjson's C (de)serializer is 5-10x
# faster, shrinking GIL-held time and the thread wake-up convoy proportionally.
# Env-gated (WORKER_ORJSON=true): monkeypatches the json BINDING of the hot modules only:
#   - requests.models.complexjson  (outbound json= payload encode + Response.json decode)
#   - pycti.utils.opencti_stix2    (import_bundle_from_json bundle parse)
#   - pycti.utils.opencti_stix2_splitter (bundle split parse)
#   - the worker's own push_handler / message_queue_consumer
# Unsupported dumps kwargs (indent, cls, separators, ...) fall back to stdlib json.
import json as _stdjson
import os


class _OrjsonShim:
    def __init__(self, orjson):
        self._orjson = orjson
        # requests probes these attributes on its json backend
        self.JSONDecodeError = _stdjson.JSONDecodeError

    def loads(self, s, **kwargs):
        if kwargs:
            return _stdjson.loads(s, **kwargs)
        return self._orjson.loads(s)

    def dumps(self, obj, **kwargs):
        default = kwargs.pop("default", None)
        if kwargs:  # indent/cls/separators/sort_keys...: stay correct, use stdlib
            if default is not None:
                kwargs["default"] = default
            return _stdjson.dumps(obj, **kwargs)
        return self._orjson.dumps(obj, default=default).decode()

    def load(self, fp, **kwargs):
        return self.loads(fp.read(), **kwargs)

    def dump(self, obj, fp, **kwargs):
        fp.write(self.dumps(obj, **kwargs))


def install_orjson_shim(logger) -> None:
    if os.getenv("WORKER_ORJSON", "false").lower() != "true":
        return
    try:
        import orjson
    except ImportError:
        logger.error("WORKER_ORJSON=true but orjson is not installed, shim skipped")
        return
    shim = _OrjsonShim(orjson)
    patched = []
    try:
        import requests.models
        requests.models.complexjson = shim
        patched.append("requests.models")
    except Exception as e:  # pylint: disable=broad-except
        logger.error("orjson shim: requests patch failed", {"reason": str(e)})
    for module_name in (
        "pycti.utils.opencti_stix2",
        "pycti.utils.opencti_stix2_splitter",
        "push_handler",
        "message_queue_consumer",
    ):
        try:
            module = __import__(module_name, fromlist=["json"])
            if hasattr(module, "json"):
                module.json = shim
                patched.append(module_name)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("orjson shim: patch failed", {"module": module_name, "reason": str(e)})
    logger.info("orjson shim installed", {"patched": patched})

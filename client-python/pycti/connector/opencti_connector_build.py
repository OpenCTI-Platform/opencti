"""Resolve connector build metadata. Never raises."""

import json
import sys
from pathlib import Path

_SENTINELS = {"", "unknown", "none", "null", "undefined"}
_SOURCES = (
    (Path("__metadata__") / "connector_manifest.json", "manifest"),  # source checkout
    (Path(".connector_version.json"), "stamp"),  # docker, CI-written
)


def _anchor_candidates():
    """Yield candidate connector directories, most reliable first."""
    main_file = getattr(sys.modules.get("__main__"), "__file__", None)
    if main_file:
        yield Path(main_file).resolve().parent  # immutable once set
    if sys.path and sys.path[0]:
        yield Path(sys.path[0]).resolve()  # survives missing __file__
    yield Path.cwd()


def _clean(value):
    """Normalize a self-reported value, or None if unusable."""
    if value is None:
        return None
    text = str(value).strip()
    # 'unknown' must NOT short-circuit the chain; '$VAR' means unexpanded shell var
    if not text or text.lower() in _SENTINELS or text.startswith("$"):
        return None
    text = "".join(c for c in text if c.isalnum() or c in "._+-")
    return text[:64] or None


def resolve(connector_root=None):
    """Return (version, slug, source). Called once, at helper init."""
    anchors = [Path(connector_root)] if connector_root else list(_anchor_candidates())
    for anchor in anchors:
        for directory in [anchor, *list(anchor.parents)[:4]]:
            for name, source in _SOURCES:
                path = directory / name
                if not path.is_file():
                    continue
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                version = _clean(data.get("version") or data.get("container_version"))
                if version:
                    return version, _clean(data.get("slug")), source
    return None, None, "unknown"

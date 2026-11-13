"""Seed a platform with procedure bundles.

Each bundle file goes through the local pycti, which converts ``x-procedure``
objects (ids, platforms, tactics, technique and vulnerability refs, report
sources) before the import. The bundle can be imported again without creating
duplicates: procedure ids are kept and relationship ids are deterministic.

The target platform needs the MITRE ATT&CK dataset, because the attack
patterns a procedure implements are not part of the bundle.

Example::

    python seed_procedures.py --url http://localhost:4000 --token TOKEN \\
        data/example-procedures.json
"""

import argparse
import collections
import json
import sys
from typing import List

from pycti import OpenCTIApiClient
from pycti.utils.opencti_procedure_utils import normalize_procedure_bundle


def seed_file(client, path: str, out=print) -> int:
    """Import one bundle file and print what happened. Returns the number of failed objects."""
    with open(path, encoding="utf-8") as file:
        bundle = json.load(file)
    # The splitter normalizes again on import and logs the same warnings; they
    # are collected here too so that they appear in this script's own output.
    _, warnings = normalize_procedure_bundle(bundle)
    procedures = sum(
        1
        for item in bundle.get("objects", [])
        if item.get("type") in ("x-procedure", "x-opencti-procedure")
    )
    # update=True is the documented way to force-merge ambiguous matches. The
    # default cleanup_inconsistent_bundle=False of the import keeps the
    # relationships to attack patterns that are on the platform, not in the file.
    result = client.stix2.import_bundle_from_file(path, update=True)
    if result is None:
        out("{}: could not be read".format(path))
        return 1
    imported, failed = result
    by_type = collections.Counter(item["type"] for item in imported)
    out(
        "{}: {} procedure(s) in the file, {} object(s) imported, {} failed".format(
            path, procedures, len(imported), len(failed)
        )
    )
    for object_type, count in sorted(by_type.items()):
        out("  {}: {}".format(object_type, count))
    for item in failed:
        out("  failed: {} {}".format(item.get("type"), item.get("id")))
    for warning in warnings:
        out("  warning: " + warning)
    return len(failed)


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", required=True, help="OpenCTI URL")
    parser.add_argument("--token", required=True, help="OpenCTI API token")
    parser.add_argument("bundles", nargs="+", metavar="BUNDLE", help="STIX bundle file")
    args = parser.parse_args(argv)

    client = OpenCTIApiClient(args.url, args.token)
    failed = sum(seed_file(client, path) for path in args.bundles)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

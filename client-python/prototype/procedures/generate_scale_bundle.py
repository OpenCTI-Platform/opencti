"""Generate a bundle of many synthetic procedures to test the library at scale.

Every procedure implements one attack pattern (``x_technique_refs``). The
output is a STIX bundle of ``x-procedure`` objects, which the pycti splitter
converts on import (see ``seed_procedures.py``). The same seed always gives
the same bundle.

Example::

    python generate_scale_bundle.py --url http://localhost:4000 --token TOKEN \\
        --mitre-id T1059.001 --mitre-id T1566.001 --count 500 --out scale.json
"""

import argparse
import json
import random
import sys
import uuid
from typing import Dict, List

VERBS = [
    "Run",
    "Launch",
    "Load",
    "Download",
    "Decode",
    "Schedule",
    "Inject",
    "Hide",
    "Collect",
    "Stage",
    "Execute",
    "Register",
]
OBJECTS = [
    "payload",
    "script",
    "backdoor",
    "loader",
    "implant",
    "command",
    "archive",
    "dropper",
    "module",
    "beacon",
    "credential dumper",
    "stager",
]
METHODS = [
    "PowerShell",
    "cmd.exe",
    "scheduled task",
    "WMI",
    "rundll32",
    "mshta",
    "bash",
    "cron job",
    "systemd service",
    "AppleScript",
    "registry run key",
    "certutil",
]
PLATFORMS = ["windows", "linux", "macos"]
CREATED = "2026-01-01T00:00:00.000Z"


def _uuid(rng: random.Random) -> str:
    """A reproducible version 4 UUID drawn from the seeded generator."""
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def build_scale_bundle(
    attack_pattern_ids: List[str], count_per_pattern: int, seed: int
) -> Dict:
    """Build a bundle of synthetic ``x-procedure`` objects.

    :param attack_pattern_ids: STIX ids of the attack patterns to implement
    :param count_per_pattern: number of procedures generated for each attack pattern
    :param seed: seed of the random generator, the same seed gives the same bundle
    :return: a STIX 2.1 bundle
    """
    rng = random.Random(seed)
    objects = []
    for attack_pattern_id in attack_pattern_ids:
        for _ in range(count_per_pattern):
            name = "{} {} via {}".format(
                rng.choice(VERBS), rng.choice(OBJECTS), rng.choice(METHODS)
            )
            objects.append(
                {
                    "type": "x-procedure",
                    "spec_version": "2.1",
                    "id": "x-procedure--" + _uuid(rng),
                    "created": CREATED,
                    "modified": CREATED,
                    "name": name,
                    "description": "Synthetic procedure generated for scale testing.",
                    "x_procedure_type": "reporting",
                    "platforms": [rng.choice(PLATFORMS)],
                    "x_technique_refs": [attack_pattern_id],
                    "confidence": rng.choice([50, 75, 85]),
                }
            )
    return {"type": "bundle", "id": "bundle--" + _uuid(rng), "objects": objects}


def resolve_attack_pattern_ids(client, mitre_ids: List[str]) -> List[str]:
    """Resolve MITRE ATT&CK ids (for example T1059.001) to attack pattern standard ids."""
    resolved = []
    for mitre_id in mitre_ids:
        attack_pattern = client.attack_pattern.read(
            filters={
                "mode": "and",
                "filters": [{"key": "x_mitre_id", "values": [mitre_id]}],
                "filterGroups": [],
            }
        )
        if attack_pattern is None:
            raise SystemExit(
                "No attack pattern with MITRE id "
                + mitre_id
                + " on the platform. Load the MITRE ATT&CK dataset first."
            )
        resolved.append(attack_pattern["standard_id"])
    return resolved


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", required=True, help="OpenCTI URL")
    parser.add_argument("--token", required=True, help="OpenCTI API token")
    parser.add_argument(
        "--mitre-id",
        action="append",
        required=True,
        dest="mitre_ids",
        help="MITRE ATT&CK id, for example T1059.001 (repeatable)",
    )
    parser.add_argument(
        "--count", type=int, default=500, help="procedures per attack pattern"
    )
    parser.add_argument("--seed", type=int, default=1, help="random seed")
    parser.add_argument("--out", required=True, help="output bundle file")
    args = parser.parse_args(argv)

    from pycti import OpenCTIApiClient

    client = OpenCTIApiClient(args.url, args.token)
    attack_pattern_ids = resolve_attack_pattern_ids(client, args.mitre_ids)
    bundle = build_scale_bundle(attack_pattern_ids, args.count, args.seed)
    with open(args.out, "w", encoding="utf-8") as file:
        json.dump(bundle, file, indent=2)
    print(
        "Wrote {} procedures for {} attack pattern(s) to {}".format(
            len(bundle["objects"]), len(attack_pattern_ids), args.out
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

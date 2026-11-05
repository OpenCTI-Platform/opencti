"""Write (or check) the goldens of the import conformance: every fixture's calls, and the
dates pycti's guess_past_date finds in dates/texts.json (dates/expected.json).

python -m tests.import_conformance.generate          # rewrite the goldens
python -m tests.import_conformance.generate --check  # fail if one is stale
"""

import json
import sys
from pathlib import Path
from typing import Callable, List, Optional

from tests.import_conformance.recorder import (
    DATES_DIR,
    EXPECTED_FILE,
    FIXTURES_DIR,
    first_difference,
    fixture_dirs,
    record,
    record_dates,
)


def serialize(golden) -> str:
    return json.dumps(golden, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _write_or_check(
    name: str,
    expected_file: Path,
    golden: str,
    check: bool,
    stale: List[str],
    describe: Optional[Callable[[str, str], Optional[str]]] = None,
) -> None:
    current = (
        expected_file.read_text(encoding="utf-8") if expected_file.exists() else None
    )
    if current == golden:
        return
    if check:
        stale.append(name)
        if current is not None and describe is not None:
            print(name, describe(current, golden))
    else:
        expected_file.write_text(golden, encoding="utf-8")
        print("written", name)


def main(check: bool) -> int:
    stale: List[str] = []
    for fixture_dir in fixture_dirs():
        _write_or_check(
            fixture_dir.relative_to(FIXTURES_DIR).as_posix(),
            fixture_dir / EXPECTED_FILE,
            serialize(record(fixture_dir)),
            check,
            stale,
            lambda current, golden: first_difference(
                json.loads(current), json.loads(golden)
            ),
        )
    _write_or_check(
        "dates", DATES_DIR / EXPECTED_FILE, serialize(record_dates()), check, stale
    )
    if stale:
        print("stale goldens:", ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main("--check" in sys.argv[1:]))

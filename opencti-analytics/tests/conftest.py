import os

import pytest


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configuration tests must not see the developer's OPENCTI_/ANALYTICS_ vars."""
    for name in list(os.environ):
        if name.startswith(("OPENCTI_", "ANALYTICS_")):
            monkeypatch.delenv(name, raising=False)

"""Regression tests ensuring pycti no longer depends on the third-party
`magic` package (python-magic / python-magic-bin), which required the
native `libmagic` shared library to be installed on the host system.

See https://github.com/OpenCTI-Platform/opencti/issues/13517
"""

import importlib

import pytest

MODULES_TOUCHED_BY_MIGRATION = [
    "pycti.api.opencti_api_client",
    "pycti.entities.opencti_external_reference",
    "pycti.entities.opencti_stix_cyber_observable",
    "pycti.entities.opencti_stix_domain_object",
]


@pytest.mark.parametrize("module_name", MODULES_TOUCHED_BY_MIGRATION)
def test_module_does_not_import_magic(module_name):
    """None of the migrated modules should reference the `magic` package."""
    module = importlib.import_module(module_name)
    assert not hasattr(module, "magic")

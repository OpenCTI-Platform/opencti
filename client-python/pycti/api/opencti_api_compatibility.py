"""Centralized OpenCTI API compatibility detection."""

from threading import RLock
from typing import Optional


class OpenCTIApiCompatibility:
    """Track platform version and API feature support."""

    def __init__(self, api):
        self.api = api
        self._lock = RLock()
        self._platform_version: Optional[str] = None
        self._connector_registration_metadata: Optional[bool] = None

    def refresh(self) -> None:
        """Refresh the platform compatibility snapshot."""
        with self._lock:
            query = """
                query ApiCompatibility {
                    about {
                        version
                    }
                    registerConnectorInput: __type(name: "RegisterConnectorInput") {
                        inputFields {
                            name
                        }
                    }
                }
            """
            result = self.api.query(query)
            data = result.get("data", {})
            self._platform_version = (data.get("about") or {}).get("version")
            input_type = data.get("registerConnectorInput") or {}
            input_fields = input_type.get("inputFields") or []
            field_names = {field["name"] for field in input_fields}
            self._connector_registration_metadata = {
                "version",
                "slug",
            }.issubset(field_names)

    def _ensure_loaded(self) -> None:
        with self._lock:
            if self._connector_registration_metadata is None:
                self.refresh()

    @property
    def platform_version(self) -> Optional[str]:
        """Return the platform version from the latest compatibility refresh."""
        self._ensure_loaded()
        return self._platform_version

    @property
    def connector_registration_metadata(self) -> bool:
        """Return whether connector registration accepts version and slug."""
        self._ensure_loaded()
        return bool(self._connector_registration_metadata)

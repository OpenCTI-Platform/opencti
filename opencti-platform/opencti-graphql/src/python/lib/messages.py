from typing import Dict

__all__ = ("MISSING_ARGUMENT",)

MISSING_ARGUMENT: Dict[str, str] = {
    "status": "error",
    "message": "Missing argument to the Python script",
}

import json
import sys

__all__ = ("return_data",)


def return_data(data):
    print(json.dumps(data))
    sys.stdout.flush()
    sys.exit(0)

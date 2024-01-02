import json
import sys

__all__ = ("return_data",)


def return_data(data):
    try:
        print_data = json.dumps(data)
        print(print_data)
    except Exception as e:
        print(json.dumps({"status": "error", "message": str(e)}))

    sys.stdout.flush()
    sys.exit(0)

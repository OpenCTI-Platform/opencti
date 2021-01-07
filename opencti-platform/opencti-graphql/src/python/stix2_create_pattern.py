import sys
import json

from stix2 import ObjectPath, EqualityComparisonExpression, ObservationExpression

PATTERN_MAPPING = {
    "Autonomous-System": ["number"],
    "Directory": ["path"],
    "Domain-Name": ["value"],
    "Email-Addr": ["value"],
    "File_md5": ["hashes", "MD5"],
    "File_sha1": ["hashes", "SHA-1"],
    "File_sha256": ["hashes", "SHA-256"],
    "File_sha512": ["hashes", "SHA-512"],
    "Email-Message_Body": ["body"],
    "Email-Message_Subject": ["subject"],
    "Email-Mime-Part-Type": ["body"],
    "IPv4-Addr": ["value"],
    "IPv6-Addr": ["value"],
    "Mac-Addr": ["value"],
    "Mutex": ["name"],
    "Network-Traffic": ["dst_port"],
    "Process": ["command_line"],
    "Process_pid": ["pid"],
    "Software": ["name"],
    "Url": ["value"],
    "User-Account": ["acount_login"],
    "Windows-Registry-Key": ["key"],
    "Windows-Registry-Value-Type": ["name"],
}


def return_data(data):
    print(json.dumps(data))
    sys.stdout.flush()
    exit(0)


def main():
    if len(sys.argv) <= 2:
        return_data(
            {"status": "error", "message": "Missing argument to the Python script"}
        )

    if sys.argv[1] == "check":
        return_data({"status": "success"})

    observable_type = sys.argv[1]
    observable_value = sys.argv[2]
    if observable_type in PATTERN_MAPPING:
        lhs = ObjectPath(
            observable_type.lower()
            if "_" not in observable_type
            else observable_type.split("_")[0].lower(),
            PATTERN_MAPPING[observable_type],
        )
        ece = ObservationExpression(EqualityComparisonExpression(lhs, observable_value))
        return_data({"status": "success", "data": str(ece)})
    else:
        return_data({"status": "unknown", "data": None})


if __name__ == "__main__":
    main()

import sys

import eql
import plyara
from parsuricata import parse_rules
from sigma.parser.collection import SigmaCollectionParser
from stix2patterns.validator import run_validator

from lib.snortparser import Parser
from lib.utils import return_data


def main():  # pylint: disable=too-many-branches
    if len(sys.argv) <= 2:
        return_data(
            {"status": "error", "message": "Missing argument to the Python script"}
        )

    if sys.argv[1] == "check":
        return_data({"status": "success"})

    pattern_type = sys.argv[1]
    indicator_value = sys.argv[2]

    if pattern_type == "stix":
        result = False
        try:
            errors = run_validator(indicator_value)
            if len(errors) == 0:
                result = True
        except:  # pylint: disable=bare-except
            result = False
        return_data({"status": "success", "data": result})

    if pattern_type == "yara":
        parser = plyara.Plyara()
        result = False
        try:
            parser.parse_string(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return_data({"status": "success", "data": result})

    if pattern_type == "sigma":
        result = False
        try:
            parser = SigmaCollectionParser(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return_data({"status": "success", "data": result})

    if pattern_type == "snort":
        result = False
        try:
            Parser(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return_data({"status": "success", "data": result})

    if pattern_type == "suricata":
        result = False
        try:
            parse_rules(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return_data({"status": "success", "data": result})

    if pattern_type == "eql":
        result = False
        try:
            with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                eql.parse_query(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return_data({"status": "success", "data": result})

    return_data({"status": "unknown", "data": None})


if __name__ == "__main__":
    main()

import sys

import eql
import plyara
from parsuricata import parse_rules
from sigma.parser.collection import SigmaCollectionParser
from snort.snort_parser import Parser
from stix2patterns.validator import run_validator
from utils.runtime_utils import return_data


def check_indicator(pattern_type, indicator_value):  # pylint: disable=too-many-branches
    if pattern_type == "stix":
        result = False
        try:
            errors = run_validator(indicator_value)
            if len(errors) == 0:
                result = True
        except:  # pylint: disable=bare-except
            result = False
        return {"status": "success", "data": result}

    if pattern_type == "yara":
        parser = plyara.Plyara()
        try:
            parser.parse_string(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return {"status": "success", "data": result}

    if pattern_type == "sigma":
        try:
            SigmaCollectionParser(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return {"status": "success", "data": result}

    if pattern_type == "snort":
        try:
            Parser(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return {"status": "success", "data": result}

    if pattern_type == "suricata":
        try:
            parse_rules(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return {"status": "success", "data": result}

    if pattern_type == "eql":
        try:
            with eql.parser.elasticsearch_syntax, eql.parser.ignore_missing_functions:
                eql.parse_query(indicator_value)
            result = True
        except:  # pylint: disable=bare-except
            result = False
        return {"status": "success", "data": result}

    return {"status": "unknown", "data": None}


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        return_data(
            {"status": "error", "message": "Missing argument to the Python script"}
        )

    if sys.argv[1] == "check":
        return_data({"status": "success"})

    data = check_indicator(sys.argv[1], sys.argv[2])
    return_data(data)

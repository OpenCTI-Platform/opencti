# coding: utf-8
import argparse

from dateutil.parser import parse

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)


def main():
    # Parameters
    parser = argparse.ArgumentParser(description="Mandatory arguments.")
    parser.add_argument(
        "--entity-type",
        dest="entity_type",
        default="Intrusion-Set",
        required=True,
        help="Type of the threat (Threat-Actor, Intrusion-Set, Campaign, X-OpenCTI,-Incident, Malware, Tool, Attack-Pattern)",
    )
    parser.add_argument(
        "--name",
        dest="name",
        required=True,
        help="Name of the threat",
    )
    parser.add_argument(
        "--created-after",
        dest="createdAfter",
        help="Indicator created before (ISO date)",
    )
    parser.add_argument(
        "--created-before",
        dest="createdBefore",
        help="Indicator created after (ISO date)",
    )
    parser.add_argument(
        "--tags",
        dest="tags",
        required=True,
        help="Tags to add or remove (separated by ,)",
    )
    parser.add_argument(
        "--operation",
        dest="operation",
        required=True,
        default="add",
        help="Operation (add/remove)",
    )
    args = parser.parse_args()

    entity_type = args.entity_type
    name = args.name
    created_after = parse(args.createdAfter).strftime("%Y-%m-%dT%H:%M:%SZ")
    created_before = parse(args.createdBefore).strftime("%Y-%m-%dT%H:%M:%SZ")
    tags = args.tags.split(",")
    operation = args.operation

    # Resolve the entity
    threat = opencti_api_client.stix_domain_object.read(
        types=[entity_type],
        filters={
            "mode": "and",
            "filters": [{"key": "name", "values": [name]}],
            "filterGroups": [],
        },
    )

    if not threat:
        raise ValueError("Cannot find the entity with the name " + name)

    # Resolve all tags
    labels = []
    for tag in tags:
        labels.append(opencti_api_client.label.create(value=tag))

    # Get indicators
    custom_attributes = """
        id
        created_at
    """

    data = {"pagination": {"hasNextPage": True, "endCursor": None}}
    while data["pagination"]["hasNextPage"]:
        after = data["pagination"]["endCursor"]
        data = opencti_api_client.indicator.list(
            first=50,
            after=after,
            customAttributes=custom_attributes,
            filters={
                "mode": "and",
                "filters": [
                    {"key": "indicates", "values": [threat["id"]]},
                    {"key": "created_at", "values": [created_after], "operator": "gt"},
                    {"key": "created_at", "values": [created_before], "operator": "lt"},
                ],
                "filterGroups": [],
            },
            orderBy="created_at",
            orderMode="asc",
            withPagination=True,
        )
        for indicator in data["entities"]:
            print("[" + indicator["created_at"] + "] " + indicator["id"])
            if operation == "add":
                for label in labels:
                    opencti_api_client.stix_domain_object.add_label(
                        id=indicator["id"], label_id=label["id"]
                    )
            elif operation == "remove":
                for label in labels:
                    opencti_api_client.stix_domain_object.remove_label(
                        id=indicator["id"], label_id=label["id"]
                    )


if __name__ == "__main__":
    main()

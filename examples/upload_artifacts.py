import argparse
import os

import magic

from pycti import OpenCTIApiClient

API_URL = "API_URL_HERE"
API_TOKEN = "API_TOKEN_HERE"

# OpenCTI instantiation
OPENCTI_API_CLIENT = OpenCTIApiClient(API_URL, API_TOKEN)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f", "--file", required=True, help="The path of the Artifact(s) to upload."
    )
    parser.add_argument(
        "-d", "--description", default="", help="The description for the Artifact."
    )
    parser.add_argument(
        "-l", "--label", default="", help="Comma separated labels for the Artifact."
    )
    parser.add_argument(
        "-r",
        "--related",
        default=None,
        help="Standard id of an object related to the Artifact.",
    )

    args = parser.parse_args()

    if os.path.isdir(args.file):
        for currentpath, folders, files in os.walk(args.file):
            for filep in files:
                upload(
                    os.path.join(currentpath, filep),
                    args.description,
                    args.label,
                    args.related,
                )

    else:
        upload(args.file, args.description, args.label, args.related)


def upload(file_path, description, labels, related_standard_id):

    file_data = b""
    with open(file_path, "rb") as f:
        file_data = f.read()

    mime_type = magic.from_buffer(file_data, mime=True)

    # Upload the file, returns the query response for the file upload
    kwargs = {
        "file_name": os.path.basename(file_path),
        "data": file_data,
        "mime_type": mime_type,
        "x_opencti_description": "",
    }

    if description:
        kwargs["x_opencti_description"] = description

    response = OPENCTI_API_CLIENT.stix_cyber_observable.upload_artifact(**kwargs)
    print(response)

    for label_str in labels.split(","):
        if label_str:
            label = OPENCTI_API_CLIENT.label.create(value=label_str)
            OPENCTI_API_CLIENT.stix_cyber_observable.add_label(
                id=response["id"], label_id=label["id"]
            )

    if related_standard_id:
        OPENCTI_API_CLIENT.stix_core_relationship.create(
            fromId=related_standard_id,
            toId=response["standard_id"],
            relationship_type="related-to",
            description=f"Related to {related_standard_id}",
        )


if __name__ == "__main__":
    main()

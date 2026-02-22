# coding: utf-8
import datetime
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the Intrusion Set
intrusion_set = opencti_api_client.intrusion_set.create(
    name="Another new Intrusion Set",
    description="Another Evil Cluster\n\n![Image example](embedded/upload_image_example.png)",
    first_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    last_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    update=True,
)

# Print
print(intrusion_set)

# Upload the file
file = opencti_api_client.stix_domain_object.add_file(
    id=intrusion_set["id"],
    file_name="./upload_image_example.png",
    embedded=True,
)
print(file)
# file is embedded and not visible under "data" tab
# it is accessible at path <OPENCTI_API_URL>/dashboard/threats/intrusion_sets/<id>/embedded/upload_image_example.png
# and can be referenced in the entity description with a local path "![Image example](embedded/upload_image_example.png)"

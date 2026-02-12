# coding: utf-8
import datetime
import os

from pycti import OpenCTIApiClient
from six import print_

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# get the file data
with open("./upload_image_example.png", "rb") as f:
    file_data = f.read()
    f.close()

# Create the Intrusion Set
intrusion_set = opencti_api_client.intrusion_set.create(
    name="Yet another new Intrusion Set",
    description="Yet Another Evil Cluster\n\n![Image example](embedded/upload_image_example.png)",
    first_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    last_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    update=True,
    files=(opencti_api_client.file("upload_image_example.png", file_data, "image/png")),
    embedded=True,
)

# Print
print(intrusion_set)

# file is embedded and not visible under "data" tab
# it is accessible at path <OPENCTI_API_URL>/dashboard/threats/intrusion_sets/<id>/embedded/upload_image_example.png
# and can be referenced in the entity description with a local path "![Image example](embedded/upload_image_example.png)"

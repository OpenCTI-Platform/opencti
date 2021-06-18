# coding: utf-8
import datetime

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

opencti_api_client.intrusion_set.create(
    name="EvilSET123",
    description="Evil Cluster",
    first_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    last_seen=datetime.date.today().strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    update=True,
)

# Get the intrusion set APT28
intrusion_set = opencti_api_client.intrusion_set.read(
    filters=[{"key": "name", "values": ["EvilSET123"]}]
)

# Delete the intrusion set
opencti_api_client.stix_domain_object.delete(id=intrusion_set["id"])

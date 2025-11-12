# coding: utf-8
import os

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")
# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

obs = opencti_api_client.stix_cyber_observable.create(
    simple_observable_key="IPv4-Addr.value", simple_observable_value="55.55.55.99"
)
indicator = opencti_api_client.stix_cyber_observable.promote_to_indicator_v2(
    id=obs.get("id")
)
print("promoted observable, new indicator is", indicator)

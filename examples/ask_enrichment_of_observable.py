# coding: utf-8
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "YOUR_TOKEN"
# Define name of INTERNAL_ENRICHMENT Connector which can enrich IPv4 addresses
connector_name = "AbuseIPDB"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the observable
observable = opencti_api_client.stix_cyber_observable.create(
    **{
        "simple_observable_key": "IPv4-Addr.value",
        "simple_observable_value": "8.8.4.4",
    }
)

# Get connector id for defined connector name
connector_list = opencti_api_client.connector.list()
connector_names = []
connector_id = ""
for connector in connector_list:
    connector_names.append(connector["name"])
    if connector["name"] == connector_name:
        connector_id = connector["id"]

if connector_id == "":
    print(f"Connector with name '{connector_name}' could not be found")
    print(f"Running connectors: {connector_names}")
    exit(0)

print("Asking for enrichment... (this might take a bit to finish)")
# Ask for enrichment
work_id = opencti_api_client.stix_cyber_observable.ask_for_enrichment(
    id=observable["id"], connector_id=connector_id
)
# Wait for connector to finish
opencti_api_client.work.wait_for_work_to_finish(work_id)

# Read the observable
obs = opencti_api_client.stix_cyber_observable.read(id=observable["id"])
print(obs)

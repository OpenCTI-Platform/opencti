# coding: utf-8
import os
import sys

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://opencti:4000")
api_token = os.getenv("OPENCTI_API_TOKEN")

csv_file_path = os.getenv("OPENCTI_CSV_FILE_PATH")
csv_mapper_name = os.getenv("OPENCTI_CSV_MAPPER_NAME")

if not api_token:
    sys.exit("Missing OPENCTI_API_TOKEN")

if not csv_file_path:
    sys.exit("Missing OPENCTI_CSV_FILE_PATH")

if not csv_mapper_name:
    sys.exit("Missing OPENCTI_CSV_MAPPER_NAME")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Upload the CSV file to the import area.
uploaded_file = opencti_api_client.upload_file(file_name=csv_file_path)
uploaded_file_id = uploaded_file["data"]["uploadImport"]["id"]

# Find the CSV mapper import connector and the requested mapper configuration.
connectors_query = """
query CsvMapperImportConnectors {
  connectorsForImport {
    id
    name
    active
    configurations {
      id
      name
      configuration
    }
  }
}
"""

connectors_result = opencti_api_client.query(connectors_query)
connectors = connectors_result["data"]["connectorsForImport"] or []

csv_connector = next(
    (
        connector
        for connector in connectors
        if connector and connector["name"] == "[FILE] CSV Mapper import"
    ),
    None,
)

if csv_connector is None:
    sys.exit("CSV mapper import connector was not found")

if not csv_connector["active"]:
    sys.exit("CSV mapper import connector is not active")

csv_mapper = next(
    (
        configuration
        for configuration in csv_connector.get("configurations", []) or []
        if configuration["name"] == csv_mapper_name
    ),
    None,
)

if csv_mapper is None:
    sys.exit(f"CSV mapper configuration was not found: {csv_mapper_name}")

# Ask OpenCTI to import the uploaded CSV with the selected mapper.
ask_import_mutation = """
mutation AskCsvMapperImport(
  $fileName: ID!
  $connectorId: String
  $configuration: String
) {
  askJobImport(
    fileName: $fileName
    connectorId: $connectorId
    configuration: $configuration
  ) {
    id
    name
    uploadStatus
  }
}
"""

import_result = opencti_api_client.query(
    ask_import_mutation,
    {
        "fileName": uploaded_file_id,
        "connectorId": csv_connector["id"],
        "configuration": csv_mapper["configuration"],
    },
)

print(import_result)

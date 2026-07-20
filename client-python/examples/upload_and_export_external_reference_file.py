# coding: utf-8
import base64
import os
import tempfile

from pycti import OpenCTIApiClient

# Variables
api_url = os.getenv("OPENCTI_API_URL", "http://localhost:4000")
api_token = os.getenv("OPENCTI_API_TOKEN", "bfa014e0-e02e-4aa6-a42b-603b19dcf159")

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Content used to verify round-tripping later on
file_content = b"debug fetch_opencti_file_by_id - sample content"

with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp_file:
    tmp_file.write(file_content)
    tmp_file_path = tmp_file.name

print("== Step 1: create an External Reference ==")
external_reference = opencti_api_client.external_reference.create(
    source_name="debug-fetch-by-id-source",
    url="https://example.com/debug-fetch-by-id",
    description="Created by upload_and_export_external_reference_file.py",
)
print(external_reference)

print("\n== Step 2: upload a file to the External Reference ==")
upload_response = opencti_api_client.external_reference.add_file(
    id=external_reference["id"],
    file_name=tmp_file_path,
)
print(upload_response)
# add_file() returns the raw GraphQL response, not a flattened dict
uploaded_file = upload_response["data"]["externalReferenceEdit"]["importPush"]

print("\n== Step 3: create a Report referencing the External Reference ==")
report = opencti_api_client.report.create(
    name="Debug fetch_opencti_file_by_id Report",
    published="2024-01-01T00:00:00Z",
    description="Created by upload_and_export_external_reference_file.py",
    externalReferences=[external_reference["id"]],
)
print(report)

print("\n== Step 4: export the Report to STIX2 (triggers fetch_opencti_file_by_id) ==")
bundle = opencti_api_client.stix2.get_stix_bundle_or_object_from_entity_id(
    entity_type="Report",
    entity_id=report["id"],
    mode="full",
    only_entity=False,
)

exported_data = None
for stix_object in bundle["objects"]:
    if stix_object.get("type") != "report":
        continue
    for exported_external_reference in stix_object.get("external_references", []):
        if exported_external_reference.get("source_name") != "debug-fetch-by-id-source":
            continue
        exported_files = exported_external_reference.get("x_opencti_files", [])
        if not exported_files:
            continue
        # the external reference may be reused across script runs (dedup on
        # source_name + url), so pick the most recently uploaded file;
        # "version" may be missing/None, so fall back to "" for sorting
        latest_file = max(exported_files, key=lambda f: f.get("version") or "")
        exported_data = latest_file["data"]

assert exported_data is not None, "file not found in exported bundle"
decoded_from_export = base64.b64decode(exported_data)
print(f"Decoded content from export: {decoded_from_export!r}")
assert decoded_from_export == file_content, "content mismatch after export round-trip!"
print("OK: exported file content matches the uploaded content")

print(
    "\n== Step 5: compare fetch_opencti_file (url-based) vs fetch_opencti_file_by_id =="
)
file_id = uploaded_file["id"]
storage_url = api_url.rstrip("/") + "/storage/get/" + file_id
data_via_url = opencti_api_client.fetch_opencti_file(
    storage_url, binary=True, serialize=True
)
data_via_id = opencti_api_client.fetch_opencti_file_by_id(
    file_id, binary=True, serialize=True
)
print(f"fetch_opencti_file (url):     {data_via_url!r}")
print(f"fetch_opencti_file_by_id:     {data_via_id!r}")
assert (
    data_via_url == data_via_id
), "url-based and id-based fetch returned different data!"
print("OK: both methods return identical content")

print("\n== Cleanup ==")
opencti_api_client.stix_domain_object.delete(id=report["id"])
opencti_api_client.external_reference.delete(id=external_reference["id"])
os.remove(tmp_file_path)
print("Done.")

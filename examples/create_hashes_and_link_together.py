# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "609caced-7610-4c84-80b4-f3a380d1939b"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create observables
hash_md5 = opencti_api_client.stix_observable.create(
    type="File-MD5",
    observable_value="16b3f663d0f0371a4706642c6ac04e42",
    description="Hash linked to Emotet",
    update=True,
)
print(hash_md5)
hash_sha1 = opencti_api_client.stix_observable.create(
    type="File-SHA1",
    observable_value="3a1f908941311fc357051b5c35fd2a4e0c834e37",
    description="Hash linked to Emotet",
    update=True,
)
print(hash_sha1)
hash_sha256 = opencti_api_client.stix_observable.create(
    type="File-SHA256",
    observable_value="bcc70a49fab005b4cdbe0cbd87863ec622c6b2c656987d201adbb0e05ec03e56",
    description="Hash linked to Emotet",
    update=True,
)
print(hash_sha256)

# Create relations
opencti_api_client.stix_observable_relation.create(
    relationship_type="corresponds",
    fromType="File-MD5",
    fromId=hash_md5["id"],
    toType="File-SHA1",
    toId=hash_sha1["id"],
    ignore_dates=True,
)
opencti_api_client.stix_observable_relation.create(
    relationship_type="corresponds",
    fromType="File-MD5",
    fromId=hash_md5["id"],
    toType="File-SHA256",
    toId=hash_sha256["id"],
    ignore_dates=True,
)
opencti_api_client.stix_observable_relation.create(
    relationship_type="corresponds",
    fromType="File-SHA1",
    fromId=hash_sha1["id"],
    toType="File-SHA256",
    toId=hash_sha256["id"],
    ignore_dates=True,
)

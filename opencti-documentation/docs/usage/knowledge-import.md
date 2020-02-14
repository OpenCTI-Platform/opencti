---
id: knowledge-import
title: Import knowledge
sidebar_label: Import knowledge
---

## Connectors

OpenCTI has a growing number of connectors, available in the [dedicated Github repository](https://github.com/OpenCTI-Platform/connectors). The connectors with type `EXTERNAL_IMPORT` allow you to automatically import CTI data from external services (ie. AlienVault, MISP, TheHive, etc.).

## User interface

You can also import knowledge manually in the user interface of the platform. You have to possibilities:

- the global import button at the top right of the screen, entities and relations from files will be imported as they are. 
- the import button available on files uploaded in `reports`, all the knowledge imported from here will be linked to the report itself.

![Import data](assets/usage/import_data.png "Import data")

## Clients / API

For instance, in the Python library, you can use the methods:

```python
from pycti import OpenCTIApiClient

# Variables
api_url = "https://demo.opencti.io"
api_token = "2b4f29e3-5ea8-4890-8cf5-a76f61f1e2b2"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# File to import
file_to_import = "./test.json"

# Import the bundle
opencti_api_client.stix2.import_bundle_from_file(file_to_import)
```
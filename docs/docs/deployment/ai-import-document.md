# Deploy on-premise AI Import Document Extraction Service

## Introduction

By default, the [Import Document AI](https://github.com/OpenCTI-Platform/connectors/tree/master/internal-import-file/import-document-ai) connector is leveraging an extraction service hosted on `https://importdoc.ariane.filigran.io`. In some cases like air-gaped environment, you may want to deploy this extraction service on-premise.  

## Prerequisites

The extraction service providing NLP (turning raw document to STIX bundles) relies on an AI model trained by Filigran.

### Requirements

| Type                     | GPU Deployment | CPU Deployment       |
|:-------------------------|:---------------|----------------------|
| Computing                | GPU            | CPU >= 3GHz          |
| RAM                      | 8GB            | 16GB                 |
| Disk Space               | 16GB           | 16GB                 |
| -                        | -              | -                    |
| Average extraction time* | 5 to 10 secs   | 30 secs to 2 minutes |

> * Depends on the size of the file.

## Login to private Filigran Docker Image Repository

```bash
docker login --username filigrancustomers
```

Then enter the token provided by your Filigran CSM or Account Manager.

## Add the container image to your stack

The image is named `filigran/import-document-ai-webservice`, you can pull it and push it into your own Docker images repositories if necessary.

> By default, the configuration below expose the service to the port `80`, feel free to change this.

```
version: '3'
services:
  service-import-document-ai-webservice:
    image: filigran/import-document-ai-webservice
    ports:
      - "80:8000"
    # Only if you have GPU
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]           
    restart: always
```

## Configure the connector

Then, you've to configure the [Import Document AI](https://github.com/OpenCTI-Platform/connectors/tree/master/internal-import-file/import-document-ai) connector to use the deployed web service:

| Parameter (config.yml)      | Environment variable       | Value                      | Description                          |
|:----------------------------|:---------------------------|:---------------------------|--------------------------------------|
| connector_web_service_url   | CONNECTOR_WEB_SERVICE_URL  | http://{YOUR_WEBSERVICE}   | The address of your new webservice   |

## Restart the connector

Restart your connector with the right configuration.

You're good to go!
---
id: version-2.0.0-connectors
title: Connectors activation
sidebar_label: Enable connectors
original_id: connectors
---

## Introduction

Connectors are standalone processes that are independant of the rest of the platform. They are using RabbitMQ to consume or push data to OpenCTI, through a dedicated queue for each instance of connector. Depending on your deployment, you can enable connectors by using the connectors Docker images or launch them manually. 

## Connector configurations

All connectors have to be able to access to the OpenCTI API. To allow this connection, they have 2 mandatory configuration parameters, the `OPENCTI_URL` and the `OPENCTI_TOKEN`. In addition of these 2 parameters, connectors have 5 other mandatory parameters that need to be set in order to get them work. 

```
- CONNECTOR_ID=ChangeMe
- CONNECTOR_TYPE=INTERNAL_EXPORT_FILE
- CONNECTOR_NAME=ExportFileStix2
- CONNECTOR_SCOPE=application/json
- CONNECTOR_CONFIDENCE_LEVEL=3
- CONNECTOR_LOG_LEVEL=info
```

> The `CONNECTOR_ID` must be a valid UUIDv4

> The `CONNECTOR_TYPE` must be a valid type, the possible types are:
> - EXTERNAL_IMPORT: from remote sources to OpenCTI STIX2 (ie. MITRE, MISP, CVE, etc.)
> - INTERNAL_IMPORT_FILE: from OpenCTI file system to OpenCTI STIX (ie. Extraction of observables from PDFs, STIX2 import, etc.)
> - INTERNAL_ENRICHMENT: from OpenCTI STIX2 to OpenCTI STIX2 (ie. Enrichment of observables though external servies, entities updates, etc.)
> - INTERNAL_EXPORT_FILE: from OpenCTI STIX2 to OpenCTI file system (ie. STIX2 export, PDF export, CSV list generation, etc.)

> The `CONNECTOR_NAME` is an arbitrary name

> The `CONNECTOR_SCOPE` is the scope handled by the connector:
> - EXTERNAL_IMPORT: entity types that have to be imported by the connectors, if the connector provide more, they will be ignored
> - INTERNAL_IMPORT_FILE: files mime types to support (application/json, ...)
> - INTERNAL_ENRICHMENT: entity types to support (Report, Hash, ...)
> - INTERNAL_EXPORT_FILE: files mime types to generate (application/pdf, ...)

> The `CONNECTOR_CONFIDENCE_LEVEL` of the connector will be used to set the `CONNECTOR_CONFIDENCE_LEVEL` of the relationships created by the connector. If a connector needs to create a relationship that already exists, it will check the current `CONNECTOR_CONFIDENCE_LEVEL` and if it is lower than its own, it will update the relationship with the new information. If it is higher, it will do nothing and keep the existing relationship.

## Docker activation

You can either directly run the Docker image of connectors or add them to your current `docker-compose.yml` file.

### Add a connector to your deployment

For instance, to enable the MISP connector, you can add a new service to your `docker-compose.yml` file:

```
  connector-misp:
    image: opencti/connector-misp:2.0.0
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=MISP
      - CONNECTOR_SCOPE=misp
      - CONNECTOR_CONFIDENCE_LEVEL=3
      - CONNECTOR_LOG_LEVEL=info
      - MISP_URL=http://localhost # Required
      - MISP_KEY=ChangeMe # Required
      - MISP_TAG=OpenCTI:\ Import # Optional, tags of events to be ingested (if not provided, import all!)
      - MISP_UNTAG_EVENT=true # Optional, remove the tag after import
      - MISP_IMPORTED_TAG=OpenCTI:\ Imported # Required, tag event after import
      - MISP_FILTER_ON_IMPORTED_TAG=true # Required, use imported tag to know which events to not ingest
      - MISP_INTERVAL=1 # Minutes
    restart: always
 ```

### Launch a standalone connector

To launch standalone connector, you can use the `docker-compose.yml` file of the connector itself. Just download the [release](https://github.com/OpenCTI-Platform/connectors/archive/{RELEASE_VERSION}.zip) and start the connector:

```
$ wget https://github.com/OpenCTI-Platform/connectors/archive/{RELEASE_VERSION}.zip
$ unzip {RELEASE_VERSION}.zip
$ cd connectors-{RELEASE_VERSION}/misp/
```

Change the configuration in the `docker-compose.yml` according to the parameters of the platform and of the targeted service. RabbitMQ credentials are the only parameters that the connector need to send data to OpenCTI. Then launch the connector:

```
$ docker-compose up
```

## Manual activation

If you want to manually launch connector, you just have to install Python 3 and pip3 for dependencies:

```
$ apt install python3 python3-pip
```

Download the [release](https://github.com/OpenCTI-Platform/connectors/archive/{RELEASE_VERSION}.zip) of the connectors:

```
$ wget https://github.com/OpenCTI-Platform/connectors/archive/{RELEASE_VERSION}.zip
$ unzip {RELEASE_VERSION}.zip
$ cd connectors-{RELEASE_VERSION}/misp/src/
```

Install dependencies and initialize the configuration:

```
$ pip3 install -r requirements.txt
$ cp config.yml.sample config.yml
```

Change the `config.yml` content according to the parameters of the platform and of the targeted service and launch the connector:

```
$ python3 misp.py
```

## Connectors status

The connector status can be displayed in the dedicated section. You will be able to see the statistics of the RabbitMQ queue of the connector:

![Connectors status](assets/installation/connectors_status.png "Connectors status")
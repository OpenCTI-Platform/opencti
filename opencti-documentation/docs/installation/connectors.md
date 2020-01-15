---
id: connectors
title: Connectors activation
sidebar_label: Enable connectors
---

## Introduction

Connectors are standalone processes that are independant of the rest of the platform. They are using RabbitMQ to consume or push data to OpenCTI, through a dedicated queue for each instance of connector. Depending on your deployment, you can enable connectors by using the connectors Docker images or launch them manually. 

## Connector configurations

All connectors have to be able to access to the OpenCTI API. To allow this connection, they have 2 mandatory configuration parameters, the `OPENCTI_URL` and the `OPENCTI_TOKEN`. In addition of these 2 parameters, connectors have  other mandatory parameters that need to be set in order to get them work. 

Example in a `docker-compose.yml` file:
```yaml
- CONNECTOR_ID=ChangeMe
- CONNECTOR_TYPE=EXTERNAL_IMPORT
- CONNECTOR_NAME=MITRE ATT&CK
- CONNECTOR_SCOPE=identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report
- CONNECTOR_CONFIDENCE_LEVEL=3
- CONNECTOR_UPDATE_EXISTING_DATA=true
- CONNECTOR_LOG_LEVEL=info
```

Example in a `config.yml` file:
```yaml
connector:
  id: 'ChangeMe'
  type: 'EXTERNAL_IMPORT'
  name: 'MITRE ATT&CK'
  scope: 'identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report'
  confidence_level: 3
  update_existing_data: True
  log_level: 'info'
```

| Configuration                 | Description                                                                                                    |
| ----------------------------- |----------------------------------------------------------------------------------------------------------------|
| `CONNECTOR_ID`                | The value must be a valid `UUIDv4`.                                                                            |
| `CONNECTOR_TYPE`              | The value must not be changed and is chosen by the connector developer.                                        |
| `CONNECTOR_NAME`              | An arbitrary name to identify the connector (useful if you have multiple instances of `MISP` for instance).    |
| `CONNECTOR_SCOPE`             | The scope handled by the connector, please refer to the connector documentation for possible values.           |
| `CONNECTOR_CONFIDENCE_LEVEL`  | The value will be used to set the `confidence_level` of relationships created by the connector.                |

## Docker activation

You can either directly run the Docker image of connectors or add them to your current `docker-compose.yml` file.

### Add a connector to your deployment

For instance, to enable the MISP connector, you can add a new service to your `docker-compose.yml` file:

```
  connector-misp:
    image: opencti/connector-misp:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=MISP
      - CONNECTOR_SCOPE=misp
      - CONNECTOR_CONFIDENCE_LEVEL=3
      - CONNECTOR_UPDATE_EXISTING_DATA=false
      - CONNECTOR_LOG_LEVEL=info
      - MISP_URL=http://localhost # Required
      - MISP_KEY=ChangeMe # Required
      - MISP_SSL_VERIFY=False # Required
      - MISP_CREATE_REPORTS=True # Required, create report for MISP event
      - MISP_REPORT_CLASS=MISP\ event # Optional, report_class if creating report for event
      - MISP_IMPORT_FROM_DATE=2000-01-01 # Optional, import all event from this date
      - MISP_IMPORT_TAGS=opencti:import,type:osint # Optional, list of tags used for import events
      - MISP_INTERVAL=1 # Required, in minutes
    restart: always
 ```

### Launch a standalone connector

To launch standalone connector, you can use the `docker-compose.yml` file of the connector itself. Just download the [release](https://github.com/OpenCTI-Platform/connectors/archive/{RELEASE_VERSION}.zip) and start the connector:

```
$ wget https://github.com/OpenCTI-Platform/connectors/archive/{RELEASE_VERSION}.zip
$ unzip {RELEASE_VERSION}.zip
$ cd connectors-{RELEASE_VERSION}/misp/
```

Change the configuration in the `docker-compose.yml` according to the parameters of the platform and of the targeted service. Then launch the connector:

```
$ docker-compose up
```

> Be careful that some connectors will try to connect to the RabbitMQ based on the RabbitMQ configuration provided for the OpenCTI platform. The connector must be able to reach RabbitMQ on the specified `hostname` and `port`.

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

> Be careful that some connectors will try to connect to the RabbitMQ based on the RabbitMQ configuration provided for the OpenCTI platform. The connector must be able to reach RabbitMQ on the specified `hostname` and `port`.

## Connectors status

The connector status can be displayed in the dedicated section. You will be able to see the statistics of the RabbitMQ queue of the connector:

![Connectors status](assets/installation/connectors_status.png "Connectors status")
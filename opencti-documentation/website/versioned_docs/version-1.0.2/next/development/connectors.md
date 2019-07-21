---
id: version-1.0.2-connectors
title: Development of connectors
sidebar_label: Connectors
original_id: connectors
---

> Available from the version 1.1.0

Connectors are the cornerstone of the OpenCTI platform and allow organizations to easily ingest new data on the platform. The OpenCTI core development team will provide as many connectors as they can but any developers can contribute to community connectors provided on the [official repository](https://github.com/OpenCTI-Platform/connectors).

## Introduction

We choose to have a very decentralized approach on connectors, in order to bring a maximum freedom to developers and vendors. So a connector on OpenCTI can be defined by **a standalone Python 3 process that pushes an understandable format of data to an ingestion queue of messages**. For the moment, only a valid STIX2 bundle is supported, by we intend to support CSV and other formats in the future.

![Connector architecture](assets/development/connector_architecture.png "Connector architecture")

## Development

Each connector must implement a long-running process that can be launched just by executing the main Python file. The only mandatory dependency is the `OpenCTIConnectorHelper` class that enables the connector to send data to OpenCTI.

### Connector configuration

The connector configuration can be based on a `config.yml` located in the same directory than the main file or in environments variables when using Docker. The only 2 mandatory fields are `name` and `confidence_level`. 


```
from pycti import OpenCTIConnectorHelper

connector_identifier = instance_name # where instance_name is lowercase and contains no special chars, unique based 

opencti_connector_helper = OpenCTIConnectorHelper(
	connector_identifier,
    config_connector,
    config_rabbitmq,
    'info' # info, warning, error
)
```
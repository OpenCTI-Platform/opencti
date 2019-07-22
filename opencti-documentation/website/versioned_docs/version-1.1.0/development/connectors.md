---
id: version-1.1.0-connectors
title: Development of connectors
sidebar_label: Connectors
original_id: connectors
---

Connectors are the cornerstone of the OpenCTI platform and allow organizations to easily ingest new data on the platform. The OpenCTI core development team will provide as many connectors as they can but any developers can contribute to community connectors provided on the [official repository](https://github.com/OpenCTI-Platform/connectors).

## Introduction

We choose to have a very decentralized approach on connectors, in order to bring a maximum freedom to developers and vendors. So a connector on OpenCTI can be defined by **a standalone Python 3 process that pushes an understandable format of data to an ingestion queue of messages**.

> For the moment, only a valid STIX2 bundle is supported, by we intend to support CSV and other formats in the future.

![Connector architecture](assets/development/connector_architecture.png "Connector architecture")

Each connector must implement a long-running process that can be launched just by executing the main Python file. The only mandatory dependency is the `OpenCTIConnectorHelper` class that enables the connector to send data to OpenCTI.

## Connector configuration

The connector configuration can be based on a `config.yml` located in the same directory than the main file or in environments variables when using Docker.

> In the configuration, the RabbitMQ configuration is mandatory, as well as the `name` and the `confidence_level` (that will be used to solve conflicts between entities or relationships).

Here is an example of a simple `config.yml` file:

```yaml
rabbitmq:
  hostname: 'localhost'
  port: 5672
  username: 'guest'
  password: 'guest'

connector:
  name: 'Connector instance'
  confidence_level: 3
  log_level: 'info'
```

> For environement variables, your connector must respect the standard mapping of configuration, replacing each list level by the char `_`. For instance, the configuration `config['connector']['server']['hostname']` can be set as an environement variable named `CONNECTOR_SERVER_HOSTNAME`.

```python
class Connector:
    def __init__(self):
        # Get configuration
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        self.config = dict()
        if os.path.isfile(config_file_path):
            config = yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            self.config_rabbitmq = config['rabbitmq']
            self.config['name'] = config['connector']['name']
            self.config['confidence_level'] = config['connector']['confidence_level']
            self.config['log_level'] = config['connector']['log_level']
        else:
            self.config_rabbitmq = dict()
            self.config_rabbitmq['hostname'] = os.getenv('RABBITMQ_HOSTNAME', 'localhost')
            self.config_rabbitmq['port'] = os.getenv('RABBITMQ_PORT', 5672)
            self.config_rabbitmq['username'] = os.getenv('RABBITMQ_USERNAME', 'guest')
            self.config_rabbitmq['password'] = os.getenv('RABBITMQ_PASSWORD', 'guest')
            self.config['name'] = os.getenv('CONNECTOR_NAME', 'Connector instance')
            self.config['confidence_level'] = int(os.getenv('CONNECTOR_CONFIDENCE_LEVEL', 3))
            self.config['log_level'] = os.getenv('CONNECTOR_LOG_LEVEL', 'info')
```

## Initialize the OpenCTI connector helper

After getting the configuration parameters of your connector, you have to initialize the OpenCTI connector helper by using the `pycti` Python library.

```python
from pycti import OpenCTIConnectorHelper

connector_identifier = instance_name # where instance_name is lowercase and contains no special chars, unique based
# connector_identifier = ''.join(e for e in self.config['name'] if e.isalnum()).lower()

self.opencti_connector_helper = OpenCTIConnectorHelper(
	connector_identifier,
    self.config, # the configuration of the connector
    self.config_rabbitmq, # the RabbitMQ configuration with hostname, port, username and password
    'info' # info, warning, error
)
```

## Send data to OpenCTI

The OpenCTI connector helper method `send_stix2_bundle` must be used to send data to OpenCTI. Other methods such as `send_csv` will be implemented in the future. The `send_stix2_bundle` function takes 2 arguments.

1. A serialized STIX2 bundle as a `string` (mandatory)
2. A `list` of entities types that should be ingested (optional)

Here is an example using the STIX2 Python library:

```python
from stix2 import Bundle

bundle = Bundle(objects=bundle_objects).serialize()
self.opencti_connector_helper.send_stix2_bundle(bundle)
```

## Examples

You can read the source code of the OpenCTI connectors directly in the [dedicated repository](https://github.com/OpenCTI-Platform/connectors).
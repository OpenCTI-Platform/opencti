---
id: version-1.1.0-connectors
title: Connectors activation
sidebar_label: Enable connectors
original_id: connectors
---

## Introduction

Connectors are standalone processes that are independant of the rest of the platform. They are using RabbitMQ to push data to OpenCTI, through a dedicated queue for each instance of connector. Depending on your deployment, you can enable connectors by using the connectors Docker images or launch them manually. 

## Connector configurations

All connectors have 2 mandatory configuration parameters, the `name` and the `confidence_level`. The `name` is the name of the instance of the connector. For instance, for the MISP connector, you can launch as many MISP connectors as you need, if you need to pull data from multiple MISP instances. 

> The `name` of each instance of connector must be unique.

> The `confidence_level` of the connector will be used to set the `confidence_level` of the relationships created by the connector. If a connector needs to create a relationship that already exists, it will check the current `confidence_level` and if it is lower than its own, it will update the relationship with the new information. If it is higher, it will do nothing and keep the existing relationship.

## Docker activation

You can either directly run the Docker image of connectors or add them to your current `docker-compose.yml` file.

### Add a connector to your deployement

For instance, to enable the MISP connector, you can add a new service to your `docker-compose.yml` file:

```
  connector-misp:
    image: opencti/connector-misp:1.1.0
    environment:
      - RABBITMQ_HOSTNAME=localhost
      - RABBITMQ_PORT=5672 
      - RABBITMQ_USERNAME=guest
      - RABBITMQ_PASSWORD=guest
      - MISP_NAME=MISP\ Circle
      - MISP_CONFIDENCE_LEVEL=3
      - MISP_URL=http://localhost
      - MISP_KEY=ChangeMe
      - MISP_TAG=OpenCTI:\ Import
      - MISP_UNTAG_EVENT=true
      - MISP_IMPORTED_TAG=OpenCTI:\ Imported
      - MISP_INTERVAL=1 # Minutes
      - MISP_LOG_LEVEL=info
    restart: always
 ```

### Launch a standalone connector

To launch standalone connector, you can use the `docker-compose.yml` file of the connector itself. Just download the [release](https://github.com/OpenCTI-Platform/connectors/archive/1.1.0.zip) and start the connector:

```
$ wget https://github.com/OpenCTI-Platform/connectors/archive/1.1.0.zip
$ unzip 1.1.0.zip
$ cd connectors-1.1.0/misp/
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

Download the [release](https://github.com/OpenCTI-Platform/connectors/archive/1.1.0.zip) of the connectors:

```
$ wget https://github.com/OpenCTI-Platform/connectors/archive/1.1.0.zip
$ unzip 1.1.0.zip
$ cd connectors-1.1.0/misp/src/
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
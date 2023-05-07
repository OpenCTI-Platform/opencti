# Overview

Let's get started and discover the OpenCTI platform! What is OpenCTI, which technical architecture is used to run the platform and what are the hardware requirements to deploy it in production.

## Architecture

The OpenCTI platform relies on several external databases and services in order to work.

<iframe
  width="100%"
  height="450"
  src="https://www.figma.com/embed?embed_host=astra&url=https://www.figma.com/file/ZjeJwkx58eu82kenRAnk1M/OpenCTI---Technology?type=whiteboard&t=W5a5STRY4FxWB4F6-1"
  allowfullscreen
></iframe>

### The GraphQL API

The API is the central part of the OpenCTI platform, allowing the *clients* (including the *frontend*) to interact with the *database* and the *broker (messaging system)*. Built in NodeJS, it implements the [GraphQL](https://graphql.org/) query language. As the API is not fully documented yet, you can explore the available methods and parameters through a GraphQL playground. An example is available on the OpenCTI [demonstration instance](https://demo.opencti.io/graphql).

### The write workers

The workers are standalone Python processes consuming messages from the RabbitMQ broker in order to do asynchronous write queries. You can launch as many workers as you need to increase the write performances. At some point, the write performances will be limited by the throughput of the database (ElasticSearch), if you have not the expected performances with 3 or 4 workers, then is will be useless to launch more and you have to think about enhancing the hardware of the database nodes (or extend your setup to a cluster).

### The connectors

The connectors are third-party pieces of software (Python processes) that can play four different roles on the platform:

You can find all currently available connector in the [OpenCTI Ecosystem](https://www.notion.so/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76).

## Infrastructure requirements

### Dependencies

Since OpenCTI has some dependencies, you can find below the minimum configuration and amount of resources needed to launch the OpenCTI platform. 

The minimal hardware requirements for all components of the platform, including the databases, are:

| CPU         | RAM       | Disk type                    | Disk space                         |
| :---------- | :-------- | :--------------------------- | :--------------------------------- |
| 6 cores     | 16GB      | SSD (recommanded) / Normal   | Depending of your content (> 32GB) |

#### ElasticSearch

ElasticSearch is also a JAVA process that needs a minimal amount of memory and CPUs.

| CPU         | RAM       | Disk type                    | Disk space                         |
| :---------- | :-------- | :--------------------------- | :--------------------------------- |
| 2 cores     | 8GB       | SSD (recommanded) / Normal   | Depending of your content (> 16GB) |

!!! info "Memory management"

    In order to setup the JAVA memory allocation, you can use the environment variable ES_JAVA_OPTS. You can find more information in the official [ElasticSearch documentation](https://www.elastic.co/guide/index.html).

#### MinIO

MinIO has a very small footprint but depending on what you intend to store on OpenCTI, it could require disk space:

| CPU         | RAM       | Disk type                    | Disk space                         |
| :---------- | :-------- | :--------------------------- | :--------------------------------- |
| 1 core      | 128MB     | Normal                       | Depending of your content (> 1GB)  |

#### Redis

Redis has a very small footprint and only needs a tiny configuration:

| CPU         | RAM       | Disk type                    | Disk space                         |
| :---------- | :-------- | :--------------------------- | :--------------------------------- |
| 1 core      | 1GB       | Normal                       | Depending of your content (> 16GB) |

!!! info "Memory management"

    You can use the option --maxmemory to limit the use. You can find more information in the Redis docker hub.

#### RabbitMQ

RabbitMQ has a very small footprint and can store messages directly on the disk if it does not have enough memory.

| CPU         | RAM       | Disk type                    | Disk space                         |
| :---------- | :-------- | :--------------------------- | :--------------------------------- |
| 1 core      | 512MB     | Normal                       | Depending of your content (> 1GB)  |

!!! info "Memory management"

    The RabbitMQ memory configuration can be found in the [RabbitMQ official documentation](https://www.rabbitmq.com/documentation.html).

### Platform

#### Application

OpenCTI platform is based on a NodeJS runtime, with a memory limit of **512MB by default**.

| CPU         | RAM       | Disk type                    | Disk space                         |
| :---------- | :-------- | :--------------------------- | :--------------------------------- |
| 2 cores     | 8GB       | Normal                       | 256MB                              |

#### Workers and connectors

OpenCTI workers and connectors are Python processes with a very small footprint. For each connector, requirements are:

| CPU         | RAM       | Disk type                    | Disk space                         |
| :---------- | :-------- | :--------------------------- | :--------------------------------- |
| 1 core      | 128MB     | Normal                       | 128MB                              |
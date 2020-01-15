---
id: version-2.1.2-requirements
title: Infrastructure requirements
sidebar_label: Infrastructure requirements
original_id: requirements
---

Since OpenCTI has some dependencies, you can find below the minimum configuration and amount of resources needed to launch the OpenCTI platform.

## Total requirements

The minimal hardware requirements for all components of the platforms including the databases are:

| CPU           | RAM           | Disk type                  | Disk space                         |
| ------------- |---------------| ---------------------------|------------------------------------|
| 6 cores       | 16GB          | SSD (recommanded) / Normal | Depending of your content (> 32GB) |

## Databases

### Grakn 

Grakn is composed of 2 JAVA processes, one for Grakn itself and the other one for Cassandra. Each process requires a minimum of 4GB of memory. So Grakn needs:

| CPU           | RAM           | Disk type                  | Disk space                         |
| ------------- |---------------| ---------------------------|------------------------------------|
| 2 cores       | 8GB           | SSD                        | Depending of your content (> 16GB) |

> In order to setup the JAVA memory allocation, you can use the environment variable `SERVER_JAVAOPTS` and `STORAGE_JAVAOPTS`. You can find more information in the [official Grakn documentation](https://dev.grakn.ai/docs).

### ElasticSearch

ElasticSearch is also a JAVA process that needs a minimal amount of memory and CPUs.

| CPU           | RAM           | Disk type                  | Disk space                         |
| ------------- |---------------| ---------------------------|------------------------------------|
| 2 cores       | 1GB            | Normal                    | Depending of your content (> 16GB) |

> In order to setup the JAVA memory allocation, you can use the environment variable `ES_JAVA_OPTS`. You can find more information in the [official ElasticSearch documenation](ttps://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html).

### MinIO

MinIO has a very small footprint but depending on what you intend to store on OpenCTI, it could require disk space:

| CPU           | RAM           | Disk type                  | Disk space                        |
| ------------- |---------------| ---------------------------|-----------------------------------|
| 1 core        | 128MB         | Normal                     | 1GB                               |

### Redis

Redis has a very small footprint and only needs a tiny configuration:

| CPU           | RAM           | Disk type                  | Disk space                        |
| ------------- |---------------| ---------------------------|-----------------------------------|
| 1 core        | 128MB         | Normal                     | 128MB                             |

> You can use the option `--maxmemory` to limit the usage. You can find more information in the [Redis docker hub](https://hub.docker.com/r/bitnami/redis/).

### RabbitMQ

RabbitMQ has a very small footprint until and can store messages directly on the disk if it does not have enough memory.

| CPU           | RAM           | Disk type                  | Disk space                        |
| ------------- |---------------| ---------------------------|-----------------------------------|
| 1 core        | 128MB         | Normal                     | 128MB                             |

> The RabbitMQ memory configuration can be find in the [RabbitMQ official documentation](https://www.rabbitmq.com/memory.html).

### Total

The requirements for the databases infrastructure of OpenCTI are:

| CPU           | RAM           | Disk type                  | Disk space                         |
| ------------- |---------------| ---------------------------|------------------------------------|
| 4 cores       | 12GB          | SSD (recommanded) / Normal | Depending of your content (> 32GB) |

## Application

### Platform

OpenCTI platform is based on a NodeJS runtime, with a memory limit of **512MB by default**.

| CPU           | RAM           | Disk type                  | Disk space                        |
| ------------- |---------------| ---------------------------|-----------------------------------|
| 1 core        | 512MB         | Normal                     | 256MB                             |

### Workers and connectors

OpenCTI workers and connectors are Python processes with a very small footprint. For each connector, requirements are:

| CPU           | RAM           | Disk type                  | Disk space                        |
| ------------- |---------------| ---------------------------|-----------------------------------|
| 1 core        | 128MB         | Normal                     | 128MB                             |
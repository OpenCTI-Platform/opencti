---
id: version-1.1.0-requirements
title: Infrastructure requirements
sidebar_label: Infrastructure requirements
original_id: requirements
---

Since OpenCTI has some dependencies, you can find below the minimum configuration and amount of resources needed to launch the OpenCTI platform.

## Total requirements

The minimal hardware requirements for all components of the platforms including the databases are:

>- CPU: 6
>- RAM: 16G
>- Disk: SSD (recommanded) / Normal
>- Space: Depending of your content (> 32G)

## Databases

### Grakn 

Grakn is composed of 2 JAVA processes, one for Grakn itself and the other one for Cassandra. Each process requires a minimum of 4GB of memory. So Grakn needs:

>- CPU: 2
>- RAM: 8G
>- Disk: SSD

In order to setup the JAVA memory allocation, you can use the environment variable `SERVER_JAVAOPTS` and `STORAGE_JAVAOPTS`.  You can find more information in the [official Grakn documentation](https://dev.grakn.ai/docs).

### ElasticSearch

ElasticSearch is also a JAVA process that needs a minimal amount of memory and CPUs.

>- CPU: 2
>- RAM: 1G
>- Disk: Normal

In order to setup the JAVA memory allocation, you can use the environment variable `ES_JAVA_OPTS`. You can find more information in the [official ElasticSearch documenation](ttps://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html).

### Redis

Redis has a very small footprint and only needs a tiny configuration:

>- CPU: 1
>- RAM: 128M
>- Disk: Normal

You can use the option `--maxmemory` to limit the usage. You can find more information in the [Redis docker hub](https://hub.docker.com/r/bitnami/redis/).

### RabbitMQ

RabbitMQ has a very small footprint until and can store messages directly on the disk if it does not have enough memory.

>- CPU: 1
>- RAM: 128M
>- Disk: Normal

The RabbitMQ memory configuration can be find in the [RabbitMQ official documentation](https://www.rabbitmq.com/memory.html).

### Total

The requirements for the databases infrastructure of OpenCTI are:

>- CPU: 4
>- RAM: 12G
>- Disk: SSD (recommanded) / Normal

## Application

### Platform

OpenCTI platform is based on a NodeJS runtime, with a memory limit of **512MB by default**.

>- CPU: 1
>- RAM: 512M
>- Disk: Normal

### Workers and connectors

OpenCTI workers and connectors are Python processes with a very small footprint.

>- CPU: 1
>- RAM: 128M
>- DIsk: Normal
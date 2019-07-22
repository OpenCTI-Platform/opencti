---
id: version-1.1.0-docker
title: Docker installation
sidebar_label: Using Docker
original_id: docker
---

OpenCTI could be deployed using the *docker-compose* command.

## Clone the repository

```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/OpenCTI-Platform/opencti.git
$ cd opencti/opencti-docker
```

### Configure the environement

Before running the docker-compose command, please change the admin token (we advise you to generate a [uuidv4](https://www.uuidgenerator.net/) for it) and password of the application in the file `docker-compose.yml`:

```bash
- APP__ADMIN__PASSWORD=admin
- APP__ADMIN__TOKEN=ChangeMe
```

And the change the variable `OPENCTI_TOKEN` (for `worker-import` and `worker-export`) according to the value of `APP__ADMIN__TOKEN`

```bash
- OPENCTI_TOKEN=ChangeMe
```

As OpenCTI has a dependency to ElasticSearch, you have to set the `vm.max_map_count` before running the containers, as mentionned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sysctl -w vm.max_map_count=262144 
```

## Run

In order to have the best experience with docker, we recommend to use the docker stack feature. 
In this mode we will have the capacity to easily scale your deployment.

### In Swarn or Kubernetes
```bash
$ docker stack deploy -c docker-compose.yml opencti
```

### In standard docker
```bash
$ docker-compose up --compatibility
```

You can now go to http://localhost:8080 and log in with username `admin@opencti.io` and password `admin`.

## Data persistence

If you wish your OpenCTI data to be persistent in production, you should be aware of the  `volumes` section for both `Grakn` and `ElasticSearch` services in the `docker-compose.yml`.

## Memory configuration

OpenCTI default docker compose doesnt provides any specific memory configuration. 
But if you want to adapt some dependencies configuration, you can find some links below.

### Opencti - platform

OpenCTI platform is based on a nodeJS runtime, with a memory limit of 512MB by default.
We doesnt provide any option to change this limit today. If you encounter any OutOfMemory exception, please create a github issue.

### Opencti - worker and connector

OpenCTI worker and connectors are based on Python If you want to limit the memory of the process we recommend to use directly docker to do that.
You can find more information at https://docs.docker.com/compose/compose-file/. 

If you dont use docker stack, think about `--compatibility` option.

### Grakn 

Grakn is a Java process that rely on Cassandra (also a Java process). In order to setup the java memory allocation, you can use the environment variable `SERVER_JAVAOPTS` and `STORAGE_JAVAOPTS`. 

The current recommendation is `-Xms4G` for both options.

You can find more information at https://dev.grakn.ai/docs/.

### Elasticsearch

Elastic is also a Java process. In order to setup the java memory allocation, you can use the environment variable `ES_JAVA_OPTS`. 

The minimal recommended option today is `-Xms512M -Xmx512M`.

More information can be find at https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html.

### Redis

Redis have a very small footprint and only provides an option to limit the maximum amount of memory that can be used by the process.

You can use the option `--maxmemory` to limit the usage. 

More information can be find at https://hub.docker.com/r/bitnami/redis/.

### RabbitMQ

The RabbitMQ memory configuration can be find at https://www.rabbitmq.com/memory.html. Basically RabbitMQ will consumed memory until a specific threshold.
So it should be configure along with the docker memory limitation.
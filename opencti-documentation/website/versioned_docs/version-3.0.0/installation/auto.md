---
id: version-3.0.0-auto
title: Automatic installation
sidebar_label: Automatic installation
original_id: auto
---


# Virtual machine template

OpenCTI could be deployed for **testing purposes** with a provided OVA file.

## Download the OVA file

```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ wget https://releases.opencti.io/opencti-release-{RELEASE_VERSION}.ova
```

Then open the OVA file with VirtualBox or convert the OVA to another type of virtual machine image.

> This virtual machine image includes an SSH Server, default login is `opencti` and default password `opencti`.

# Using Docker

OpenCTI could be deployed using the *docker-compose* command.

## Clone the repository

```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/OpenCTI-Platform/docker.git
$ cd docker
```

### Configure the environment

Before running the docker-compose command, please change the admin token (this token must be a [valid UUID](https://www.uuidgenerator.net/)) and password of the application in the file `docker-compose.yml`:

```yaml
- APP__ADMIN__PASSWORD=ChangeMe
- APP__ADMIN__TOKEN=ChangeMe
```

And change the variable `OPENCTI_TOKEN` (for the `worker` and all connectors) according to the value of `APP__ADMIN__TOKEN`

```yaml
- OPENCTI_TOKEN=ChangeMe
```

As OpenCTI has a dependency to ElasticSearch and Grakn, you have to set the `vm.max_map_count` before running the containers, as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sysctl -w vm.max_map_count=1048575
```

To make this parameter persistent, please update your file `/etc/sysctl.conf` and add the line:
```bash
$ vm.max_map_count=1048575
```

## Run

In order to have the best experience with Docker, we recommend to use the Docker stack feature. In this mode we will have the capacity to easily scale your deployment.

```bash
$ env $(cat .env | grep ^[A-Z] | xargs) docker stack deploy --compose-file docker-compose.yml opencti
```

> In some configuration, Grakn could fail to start with the following error: `Starting Storage.....FAILED!`
> You can restart it by using the command `$ docker service update --force opencti_grakn`.

You can also deploy with the standard Docker command:

```bash
$ docker-compose --compatibility up
```

You can now go to http://localhost:8080 and log in with the credentials configured in your environment variables.

### Update the stack or delete the stack

```bash
$ docker service update --force service_name
$ docker stack rm opencti
```

### Behind a reverse proxy

If you want to use OpenCTI behind a reverse proxy with a context path, like `https://myproxy.com/opencti`, please change the base_path configuration.

```yaml
- APP__BASE_PATH=/opencti
```
By default OpenCTI use Websockets so dont forget to configure your proxy for this usage.


## Data persistence

If you wish your OpenCTI data to be persistent in production, you should be aware of the  `volumes` section for `Grakn`, `ElasticSearch` and `MinIO` services in the `docker-compose.yml`.

Here is an example of volumes configuration:

```yaml
volumes:
  grakndata:
    driver: local
    driver_opts:
      o: bind
      type: none
  esdata:
    driver: local
    driver_opts:
      o: bind
      type: none
  s3data:
    driver: local
    driver_opts:
      o: bind
      type: none      
```

## Memory configuration

OpenCTI default `docker-compose.yml` file does not provide any specific memory configuration. But if you want to adapt some dependencies configuration, you can find some links below.

### OpenCTI - Platform

OpenCTI platform is based on a NodeJS runtime, with a memory limit of **512MB by default**. We do not provide any option to change this limit today. If you encounter any `OutOfMemory` exception, please open a [Github issue](https://github.com/OpenCTI-Platform/opencti/issues/new?assignees=&labels=&template=bug_report.md&title=).

### OpenCTI - Workers and connectors

OpenCTI workers and connectors are Python processes. If you want to limit the memory of the process we recommend to directly use Docker to do that. You can find more information in the [official Docker documentation](https://docs.docker.com/compose/compose-file/). 

> If you do not use Docker stack, think about `--compatibility` option.

### Grakn 

Grakn is a JAVA process that rely on Cassandra (also a JAVA process). In order to setup the JAVA memory allocation, you can use the environment variable `SERVER_JAVAOPTS` and `STORAGE_JAVAOPTS`. 

> The current recommendation is `-Xms4G` for both options.

You can find more information in the [official Grakn documentation](https://dev.grakn.ai/docs).

### ElasticSearch

ElasticSearch is also a JAVA process. In order to setup the JAVA memory allocation, you can use the environment variable `ES_JAVA_OPTS`. 

> The minimal recommended option today is `-Xms512M -Xmx512M`.

You can find more information in the [official ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html).

### Redis

Redis has a very small footprint and only provides an option to limit the maximum amount of memory that can be used by the process. You can use the option `--maxmemory` to limit the usage. 

You can find more information in the [Redis docker hub](https://hub.docker.com/r/bitnami/redis/).

### MinIO

MinIO is a small process and does not require a high amount of memory. More information are available for Linux here on the [Kernel tuning guide](https://github.com/minio/minio/tree/master/docs/deployment/kernel-tuning).

### RabbitMQ

The RabbitMQ memory configuration can be find in the [RabbitMQ official documentation](https://www.rabbitmq.com/memory.html). Basically RabbitMQ will consumed memory until a specific threshold. So it should be configure along with the Docker memory limitation.

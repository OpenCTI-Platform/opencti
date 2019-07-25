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
- APP__ADMIN__PASSWORD=ChangeMe
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

### In Swarm or Kubernetes
```bash
$ docker stack deploy -c docker-compose.yml opencti
```

### In standard Docker
```bash
$ docker-compose --compatibility up 
```

You can now go to http://localhost:8080 and log in with the crendetials configured in your environement variables.

## Data persistence

If you wish your OpenCTI data to be persistent in production, you should be aware of the  `volumes` section for both `Grakn` and `ElasticSearch` services in the `docker-compose.yml`.

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

You can find more information in the [official ElasticSearch documenation](ttps://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html).

### Redis

Redis has a very small footprint and only provides an option to limit the maximum amount of memory that can be used by the process. You can use the option `--maxmemory` to limit the usage. 

You can find more information in the [Redis docker hub](https://hub.docker.com/r/bitnami/redis/).

### RabbitMQ

The RabbitMQ memory configuration can be find in the [RabbitMQ official documentation](https://www.rabbitmq.com/memory.html). Basically RabbitMQ will consumed memory until a specific threshold. So it should be configure along with the Docker memory limitation.

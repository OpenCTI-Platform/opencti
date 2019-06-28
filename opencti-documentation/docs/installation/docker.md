---
id: installation-docker
title: Docker installation
sidebar_label: Using Docker
---

OpenCTI could be deployed using the *docker-compose* command.

## Clone the repository

```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/LuatixHQ/opencti.git
$ cd opencti/docker
```

### Configure the environement

Before running the docker-compose command, please change the secret key of the application in the file *docker-compose.yml*
```bash
- APP__SECRET=ChangeMe
```

As OpenCTI has a dependency to ElasticSearch, you have to set the *vm.max_map_count* before running the containers, as mentionned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sysctl -w vm.max_map_count=262144 
```

## Run

```bash
$ docker-compose up
```

You can now go to http://localhost:8080 and log in with username *admin@opencti.io* and password *admin*.

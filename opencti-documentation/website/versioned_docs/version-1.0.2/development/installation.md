---
id: version-1.0.2-installation
title: Development environment installation
sidebar_label: Development environment
original_id: installation
---

## Prerequisites

- Docker
- Node.JS (>= 10)
- Python (>= 3)
- Yarn (>= 1.16)

### Installation of dependencies (Ubuntu 18.04)

```bash
$ sudo apt-get install nodejs python3 python3-pip
$ sudo curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
$ sudo echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
$ sudo apt-get update && sudo apt-get install yarn
```

### Docker stack

As OpenCTI has a dependency to ElasticSearch, you have to set the *vm.max_map_count* before running the containers, as mentionned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sysctl -w vm.max_map_count=262144
```

* Grakn (Database) - *localhost/48555*
* Elastic search (Index and search) - *localhost/9200*
* Redis (Distribution cache for websocket events) - *localhost/6379*
* RabbitMQ (Message broker for background tasks) - *localhost/5672*

```bash
$ docker-compose -f ./docker/docker-compose-dev.yml up -d
```

## Clone the project

```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ git clone --recursive https://github.com/Luatix/opencti.git
$ cd opencti
```

## Application dependencies

### Install the API dependencies

```bash
$ cd opencti-graphql
$ yarn install
```

### Install the frontend dependencies
```bash
$ cd ../opencti-front
$ yarn install
```

### Install the worker dependencies

```bash
$ pip3 install -r requirements.txt
```

### Install the integration dependencies

```bash
$ pip3 install -r requirements.txt
```

## Config and run

### GraphQL API

#### Configure

```bash
$ cp config/default.json config/development.json
```
By default the configuration match the docker stack configuration.

#### Start

```bash
$ cd opencti-graphql
$ yarn start
```

The first execution will create and migrate the schema. The admin token will be generated and printed in the console. You need to copy this token for configuration of the worker / integration.
```bash
Token for user admin: <OpenCTI token>
```

### Worker

#### Configure

```bash
$ cd opencti-worker
$ cp config.yml.sample config.yml
```
Change the *config.yml* file according to your <OpenCTI token>

#### Start

```bash
$ python3 worker_export.py &
$ python3 worker_import.py &
```

### Integration

#### Configure

```bash
$ cd opencti-integration
$ cp config.yml.sample config.yml
```
Change the *config.yml* file according to your <OpenCTI token>

#### Start

```bash
$ python3 connectors_scheduler.py
```

### Frontend

#### Start

```bash
$ cd opencti-frontend
$ yarn start
```

The default username is *admin@opencti.io* and the password is *admin*. Login and get the administrator token in your profile.

## Build for production use

### Build the application

```bash
$ cd opencti-frontend
$ yarn build
$ cd ../opencti-graphql
$ yarn build
```

### Start the production package

```bash
$ yarn serv
```

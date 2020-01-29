---
id: installation
title: Development environment installation
sidebar_label: Development environment
---

## Prerequisites

| Component     | Version               | Link                                                      |
| ------------- |-----------------------| ----------------------------------------------------------|
| Docker        | `>= 19.*`             | https://docs.docker.com/install                           |
| NodeJS        | `>= 12.* && < 13.0.0` | https://nodejs.org/en/download                            |
| Yarn          | `>= 1.16`             | https://yarnpkg.com/getting-started/install               |
| Python        | `>= 3.6`              | https://www.python.org/downloads                          |


### Installation of dependencies (Ubuntu 19.10)

If you are on a version of Debian/Ubuntu prior to 19.04, please refer to this [GIthub issue](https://github.com/OpenCTI-Platform/opencti/issues/413).

```bash
$ sudo apt-get install nodejs python3 python3-pip
$ sudo curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
$ sudo echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
$ sudo apt-get update && sudo apt-get install yarn
```

### Docker stack

As OpenCTI has a dependency to ElasticSearch, you have to set the *vm.max_map_count* before running the containers, as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sysctl -w vm.max_map_count=262144
```

Clone the latest version of the dev docker compose and start

```bash
$ git clone https://github.com/OpenCTI-Platform/docker.git
$ cd docker
$ docker-compose -f ./docker-compose-dev.yml up -d
```

## Clone the project

```bash
$ git clone https://github.com/OpenCTI-Platform/opencti.git
$ cd opencti
```

## Application dependencies

### Install the API dependencies

```bash
$ cd opencti-platform/opencti-graphql
$ yarn install
```

### Install the frontend dependencies
```bash
$ cd ../opencti-front
$ yarn install
```

### Install the worker dependencies

```bash
$ cd ../../opencti-worker/src
$ pip3 install -r requirements.txt
```

## Config and run

### GraphQL API

#### Configure

```bash
$ cd ../../opencti-platform/opencti-graphql
$ cp config/default.json config/development.json
```
By default the configuration match the docker stack configuration.
You just need to change the user part:
```bash
"admin": {
  "email": "admin@opencti.io",
  "password": "ChangeMe",
  "token": "ChangeMe"
}
```

#### Start

```bash
$ cd opencti-graphql
$ yarn start
```

The first execution will create and migrate the schema.

### Worker

#### Configure

```bash
$ cd opencti-worker
$ cp config.yml.sample config.yml
```
Change the *config.yml* file according to your <admin token>

#### Start

```bash
$ python3 worker.py &
```

### Frontend

#### Start

```bash
$ cd opencti-frontend
$ yarn start
```

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

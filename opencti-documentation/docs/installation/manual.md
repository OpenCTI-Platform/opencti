---
id: manual
title: Manual installation
sidebar_label: Manual deployment
---

## Prerequisites

| Component                   | Version               | Link                                                      |
| ----------------------------|-----------------------| ----------------------------------------------------------|
| NodeJS                      | `>= 12.* && < 13.0.0` | https://nodejs.org/en/download                            |
| Python                      | `>= 3.6`              | https://www.python.org/downloads                          |
| Grakn Core                  | `=== 1.6.1`           | https://grakn.ai/download#core                            |
| ElasticSearch               | `>= 7.5`              | https://www.elastic.co/downloads/elasticsearch            |
| MinIO                       | `>= 20191012`         | https://min.io/download                                   |
| Redis                       | `>= 3.0`              | https://redis.io/download                                 |
| RabbitMQ                    | `>= 3.7`              | https://www.rabbitmq.com/download.html                    |
| RabbitMQ Management plugin  | `>= 3.7`              | https://www.rabbitmq.com/management.html                  |

## Prepare the installation

### Installation of dependencies

You have to install all the needed dependencies for the main application and the workers. The example below if for Ubuntu:

```bash
$ sudo apt-get install nodejs npm python3 python3-pip 
```

### Download the application files

Download and extract the latest release file.

```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ wget https://github.com/OpenCTI-Platform/opencti/releases/download/{RELEASE_VERSION}/opencti-release-{RELEASE_VERSION}.tar.gz
$ tar xvfz opencti-release-{RELEASE_VERSION}.tar.gz
```

## Install the main platform

### Configure the application

The main application has just one JSON configuration file to change and a few Python modules to install

```bash
$ cd opencti
$ cp config/default.json config/production.json
```

Change the *config/production.json* file according to your configuration of Grakn, Redis, ElasticSearch, RabbitMQ and default credentials (the `ADMIN_TOKEN` must be a [valid UUID](https://www.uuidgenerator.net/)).

### Install the Python modules
```bash
$ cd src/utils/stix2
$ pip3 install -r requirements.txt
$ cd ../../..
```

### Start the application

The application is just a NodeJS process, the creation of the database schema and the migration will be done at starting.

```bash
$ yarn serv
```

The default username and password are those you put in the `config/production.json` file.

## Install the worker

The OpenCTI worker is used to write the data coming from the RabbitMQ messages broker.

#### Configure the worker

```bash
$ cd worker
$ pip3 install -r requirements.txt
$ cp config.yml.sample config.yml
```

Change the *config.yml* file according to your OpenCTI token.

#### Start as many workers as you need
```bash
$ python3 worker.py &
$ python3 worker.py &
```

## Upgrade the platform

> If you are upgrading from Grakn 1.5.9 to Grakn 1.6.1, you need to be aware of the manual migration procedure for keep your old data, as documented in the [Grakn documentation](https://dev.grakn.ai/docs/running-grakn/install-and-run).

When upgrading the platform, you have to replace all files and restart the platform, the schema migrations will be done automatically:

```bash
$ yarn serv
```
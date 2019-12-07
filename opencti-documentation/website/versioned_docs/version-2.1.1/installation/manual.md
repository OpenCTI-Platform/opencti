---
id: version-2.1.1-manual
title: Manual installation
sidebar_label: Manual deployment
original_id: manual
---

## Prerequisites

- Node.JS (>= 12.* < 13.0.0)
- Grakn (== 1.5.9)
- Redis (>= 3.0)
- ElasticSearch (>= 7.5)
- Minio (>= 20191012)
- RabbitMQ (>= 3.7)

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

The main application has just one JSON configuration file to change.

```bash
$ cd opencti
$ cp config/default.json config/production.json
```

Change the *config/production.json* file according to your configuration of Grakn, Redis, ElasticSearch, RabbitMQ and default credentials (the `ADMIN_TOKEN` must be a [valid UUID](https://www.uuidgenerator.net/)).

### Start the application

The application is just a NodeJS process, the creation of the database schema and the migration will be done at starting.

```bash
$ node dist/server.js &
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

When upgrading the platform, you have to replace all files and run the migrations and the schema commands to get updates:

```bash
$ npm run schema
$ npm run migrate
```

Then start the platform.
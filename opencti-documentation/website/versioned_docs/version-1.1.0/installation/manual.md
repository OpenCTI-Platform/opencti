---
id: version-1.1.0-manual
title: Manual installation
sidebar_label: Manual deployment
original_id: manual
---

## Prerequisites

- Node.JS (>= 10)
- Grakn (>= 1.5.7)
- Redis (>= 3.0)
- ElasticSearch (== 6.x.x)
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
$ wget https://github.com/OpenCTI-Platform/opencti/releases/download/1.1.0/opencti-release.tar.gz
$ tar xvfz opencti-release.tar.gz
```

## Install the main platform

### Configure the application

The main application has just one JSON configuration file to change.

```bash
$ cd opencti
$ cp config/default.json config/production.json
```

Change the *config/production.json* file according to your configuration of Grakn, Redis, ElasticSearch, RabbitMQ and default credentials.

### Database schema and initial data

After the configuration, you can create your database schema and add initial data.

```bash
$ npm run schema
$ npm run migrate
```

### Start the application

The application is just a NodeJS process.

```bash
$ node dist/server.js &
```

The default username and password are those you put in the `config/production.json` file.

## Install the workers

2 different workers must be configured to allow the platform to import and export data. One is for import and the other for export.

### Install the import worker

#### Configure the import worker

Just copy the worker directory to a new one, named `worker-import`.

```bash
$ cp -a worker worker-import
$ cd worker-import
$ cp config.yml.sample config.yml
```

Change the *config.yml* file according to your OpenCTI token and RabbitMQ configuration.

> The worker type must be set to "import"

#### Start as many workers as you need
```bash
$ python3 worker.py &
$ python3 worker.py &
```

### Install the export worker

#### Configure the export worker

Just copy the worker directory to a new one, named `worker-export`.

```bash
$ cd ..
$ cp -a worker worker-export
$ cd worker-export
$ cp config.yml.sample config.yml
```

Change the *config.yml* file according to your OpenCTI token and RabbitMQ configuration.

> The worker type must be set to "export"

#### Start as many workers as you need
```bash
$ python3 worker.py &
$ python3 worker.py &
```
# Installation

All components of OpenCTI are shipped both as [Docker images](https://hub.docker.com/u/opencti) and manual [installation packages](https://github.com/OpenCTI-Platform/opencti/releases).

!!! note "Production deployment"
    
    For production deployment, we recommend to deploy all components in containers, including dependencies, using native cloud services or orchestration systems such as [Kubernetes](https://kubernetes.io).

    To have more details about deploying OpenCTI and its dependencies in cluster mode, please read the [dedicated section](clustering.md).

<div class="grid cards" markdown>

-   :simple-docker:{ .lg .middle } __Use Docker__

    ---

    Deploy OpenCTI using Docker and the default `docker-compose.yml` provided
    in the [docker](https://github.com/OpenCTI-Platform/docker).

    [:octicons-arrow-right-24:{ .middle } Setup](#using-docker)

-   :material-package-up:{ .lg .middle } __Manual installation__

    ---

    Deploy dependencies and launch the platform manually using the packages
    released in the [GitHub releases](https://github.com/OpenCTI-Platform/opencti/releases).

    [:octicons-arrow-right-24:{ .middle } Explore](#manual-installation)
</div>

## Using Docker

### Introduction

OpenCTI can be deployed using the *docker-compose* command.

### Pre-requisites

**:material-linux:{ .middle } Linux**

```bash
$ sudo apt install docker-compose
```

**:material-microsoft-windows:{ .middle } Windows and MacOS**

Just download the appropriate [Docker for Desktop](https://www.docker.com/products/docker-desktop) version for your operating system.

### Clone the repository

Docker helpers are available in the [Docker GitHub repository](https://github.com/OpenCTI-Platform/docker).

```bash
$ mkdir -p /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/OpenCTI-Platform/docker.git
$ cd docker
```

### Configure the environment

Before running the `docker-compose` command, the `docker-compose.yml` file should be configured. By default, the `docker-compose.yml` file is using environment variables available in the file `.env.sample`.

You can either rename the file `.env.sample` in `.env` and put the expected values or just fill directly the `docker-compose.yml` with the values corresponding to your environment.

!!! note "Configuration static parameters"
    
    The complete list of available static parameters is available in the [configuration](configuration.md) section.

Here is an example to quickly generate the `.env` file under Linux, especially all the default UUIDv4:

```bash
$ sudo apt install -y jq
$ cd ~/docker
$ (cat << EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMePlease
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
ELASTIC_MEMORY_SIZE=4G
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_REPORT_ID=$(cat /proc/sys/kernel/random/uuid)
EOF
) > .env
```

If your `docker-compose` deployment does not support `.env` files, just export all environment variables before launching the platform:

```bash
$ export $(cat .env | grep -v "#" | xargs)
```

### Memory management settings

As OpenCTI has a dependency on ElasticSearch, you have to set the `vm.max_map_count` before running the containers, as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sudo sysctl -w vm.max_map_count=1048575
```

To make this parameter persistent, add the following to the end of your `/etc/sysctl.conf`:

```bash
$ vm.max_map_count=1048575
```

### Persist data

The default for OpenCTI data is to be persistent.

In the `docker-compose.yml`, you will find at the end the list of necessary persitent volumes for the dependencies:

```yaml
volumes:
  esdata:     # ElasticSearch data
  s3data:     # S3 bucket data
  redisdata:  # Redis data
  amqpdata:   # RabbitMQ data
```

### Run OpenCTI

#### Using single node Docker

After changing your `.env` file run `docker-compose` in detached (-d) mode:

```bash
$ sudo systemctl start docker.service
# Run docker-compose in detached 
$ docker-compose up -d
```

#### Using Docker swarm

In order to have the best experience with Docker, we recommend using the Docker stack feature. In this mode you will have the capacity to easily scale your deployment. 

```bash
# If your virtual machine is not a part of a Swarm cluster, please use:
$ docker swarm init
```

Put your environment variables in `/etc/environment`:

```bash
# If you already exported your variables to .env from above:
$ sudo cat .env >> /etc/environment
$ sudo bash -c 'cat .env >> /etc/environment’
$ sudo docker stack deploy --compose-file docker-compose.yml opencti
```

!!! success "Installation done"
    
    You can now go to [http://localhost:8080](http://localhost:8080/) and log in with the credentials configured in your environment variables.

## Manual installation

### Prerequisites

### Prepare the installation

#### Installation of dependencies

You have to install all the needed dependencies for the main application and the workers. The example below is for Debian-based systems:

```bash
$ sudo apt-get install build-essential nodejs npm python3 python3-pip python3-dev
```

#### Download the application files

First, you have to [download and extract the latest release file](https://github.com/OpenCTI-Platform/opencti/releases). Then select the version to install depending of your operating system: 

**For Linux:**

- If your OS supports libc (Ubuntu, Debian, ...) you have to install the `opencti-release_{RELEASE_VERSION}.tar.gz` version.
- If your OS uses musl (Alpine, ...) you have to install the `opencti-release-{RELEASE_VERSION}_musl.tar.gz` version.

**For Windows:**

We don't provide any Windows release for now. However it is still possible to check the code out, manually install the dependencies and build the software.

```bash
$ mkdir /path/to/your/app && cd /path/to/your/app
$ wget <https://github.com/OpenCTI-Platform/opencti/releases/download/{RELEASE_VERSION}/opencti-release-{RELEASE_VERSION}.tar.gz>
$ tar xvfz opencti-release-{RELEASE_VERSION}.tar.gz
```

### Install the main platform

#### Configure the application

The main application has just one JSON configuration file to change and a few Python modules to install

```bash
$ cd opencti
$ cp config/default.json config/production.json
```

Change the *config/production.json* file according to your configuration of ElasticSearch, Redis, RabbitMQ and S3 bucket as well as default credentials (the `ADMIN_TOKEN` must be a [valid UUID](https://www.uuidgenerator.net/)).

#### Install the Python modules

```bash
$ cd src/python
$ pip3 install -r requirements.txt
$ cd ../..
```

#### Start the application

The application is just a NodeJS process, the creation of the database schema and the migration will be done at starting.

```bash
$ yarn install
$ yarn build
$ yarn serv
```

The default username and password are those you have put in the `config/production.json` file.

### Install the worker

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

!!! success "Installation done"
    
    You can now go to [http://localhost:4000](http://localhost:4000) and log in with the credentials configured in your `production.json` file.

## Appendix

## Community contributions

### Terraform

<div class="grid cards" markdown>

-   :material-cloud-cog:{ .lg .middle } __Multi-clouds Terraform scripts__

    ---

    This repository is here to provide you with a quick and easy way to deploy an OpenCTI instance in the cloud (AWS, Azure, or GCP).

    [:material-github:{ .middle } GitHub Respository](https://github.com/newcontext-oss/opencti-terraform)

-   :material-aws:{ .lg .middle } __AWS Advanced Terraform scripts__

    ---

    A Terraform deployment of OpenCTI designed to make use of native AWS Resources (where feasible). This includes AWS ECS Fargate, AWS OpenSearch, etc.

    [:material-github:{ .middle } GitHub Repository](https://github.com/QinetiQ-Cyber-Intelligence/OpenCTI-Terraform)
</div>

### Helm Charts

<div class="grid cards" markdown>

-   :material-kubernetes:{ .lg .middle } __Kubernetes Helm Charts__

    ---

    OpenCTI Helm Charts (may be out of date) for Kubernetes with a global configuration file.

    [:material-github:{ .middle } GitHub Repository](https://github.com/Ascend-Technologies/OpenCTI-HELM-CHART)
</div>

### Deploy behind a reverse proxy

If you want to use OpenCTI behind a reverse proxy with a context path, like `https://domain.com/opencti`, please change the `base_path` static parameter.

- `APP__BASE_PATH=/opencti`

By default OpenCTI use websockets so don't forget to configure your proxy for this usage, an example with `Nginx`:

```bash
location / {
    proxy_cache                 off;
    proxy_buffering             off;
    proxy_http_version          1.1;
    proxy_set_header Upgrade    $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host       $host;
    chunked_transfer_encoding   off;
    proxy_pass                  http://YOUR_UPSTREAM_BACKEND;
  }
```

### Additional memory information

#### Platform

OpenCTI platform is based on a NodeJS runtime, with a memory limit of **8GB by default**. If you encounter `OutOfMemory` exceptions, this limit could be changed:

```yaml
- NODE_OPTIONS=--max-old-space-size=8096
```

#### Workers and connectors

OpenCTI workers and connectors are Python processes. If you want to limit the memory of the process, we recommend to directly use Docker to do that. You can find more information in the [official Docker documentation](https://docs.docker.com/compose/compose-file/).

#### ElasticSearch

ElasticSearch is also a JAVA process. In order to setup the JAVA memory allocation, you can use the environment variable `ES_JAVA_OPTS`. You can find more information in the [official ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html).

#### Redis

Redis has a very small footprint on keys but will consume memory for the stream. By default the size of the stream is limited to 2 millions which represents a memory footprint around `8 GB`. You can find more information in the [Redis docker hub](https://hub.docker.com/_/redis).

#### MinIO / S3 Bucket

MinIO is a small process and does not require a high amount of memory. More information are available for Linux here on the [Kernel tuning guide](https://github.com/minio/minio/tree/master/docs/deployment/kernel-tuning).

#### RabbitMQ

The RabbitMQ memory configuration can be find in the [RabbitMQ official documentation](https://www.rabbitmq.com/memory.html). RabbitMQ will consumed memory until a specific threshold, therefore it should be configure along with the Docker memory limitation.

# Installation

All components of OpenCTI are shipped both as [Docker images](https://hub.docker.com/u/opencti) and manual [installation packages](https://github.com/OpenCTI-Platform/opencti/releases).

!!! note "Production deployment"

    For production deployment, we recommend deploying all components in containers, including dependencies, using native cloud services or orchestration systems such as [Kubernetes](https://kubernetes.io).

    To get more details about deploying OpenCTI and its dependencies in cluster mode, please read the [dedicated section](clustering.md).

<div class="grid cards" markdown>

-   :simple-docker:{ .lg .middle } __Use Docker__

    ---

    Deploy OpenCTI using Docker and the default `docker-compose.yml` provided
    in the [docker repository](https://github.com/OpenCTI-Platform/docker).

    [:octicons-arrow-right-24:{ .middle } Setup](#using-docker)

-   :material-package-up:{ .lg .middle } __Manual installation__

    ---

    Deploy dependencies and launch the platform manually using the packages
    released in the [GitHub releases](https://github.com/OpenCTI-Platform/opencti/releases).

    [:octicons-arrow-right-24:{ .middle } Explore](#manual-installation)
</div>

!!! tip "Docker deployment of the full XTM suite (OpenCTI - OpenAEV - OpenGRC)"

    If you're looking for information about the deployment of the full eXtended Threat Management (XTM) suite using Docker, please refer [to this repository and documentation](https://github.com/FiligranHQ/xtm-docker).

## Using Docker

OpenCTI can be deployed using the *docker-compose* command.

!!! note "Deploy FIPS 140-2 compliant components"

    We provide FIPS 140-2 compliant images. Please read the [dedicated documentation](../reference/fips.md) to understand how to deploy OpenCTI in FIPS-compliant mode.

### Prerequisites

**:material-linux:{ .middle } Linux**

```bash
sudo apt remove $(dpkg --get-selections docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc | cut -f1)
# Add Docker's official GPG key:
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo apt update
```

**:material-microsoft-windows:{ .middle } Windows and MacOS**

```bash
winget install Docker.DockerDesktop Git.Git --accept-package-agreements --accept-source-agreements
```

### Clone the repository

Docker helpers are available in the [Docker GitHub repository](https://github.com/OpenCTI-Platform/docker).

```bash
mkdir -p /path/to/your/app && cd /path/to/your/app
git clone https://github.com/OpenCTI-Platform/docker.git
cd docker
```

### Configure the environment

!!! warning "ElasticSearch / OpenSearch configuration"

    - If you are installing from scratch, Filigran strongly recommends that you add the following ElasticSearch / OpenSearch parameter in `docker-compose.yml`:

    ```bash
      elasticsearch:
        environment:
          - thread_pool.search.queue_size=5000
    ```

    💡 This parameter is already present in the Docker GitHub repository files.

    - Check the [OpenCTI Integration User Permissions in OpenSearch/ElasticSearch](rollover.md#opencti-integration-user-permissions-in-opensearchelasticsearch) for detailed information about the user permissions required for the OpenSearch/ElasticSearch integration.

!!! warning "RabbitMQ configuration"

    - If you are installing from scratch, Filigran strongly recommends that you add the following RabbitMQ parameter in `rabbitmq.conf`:

    ```bash
    max_message_size = 536870912
    consumer_timeout = 86400000
    ```

    💡 This parameter is already present in the Docker GitHub repository files.
    
Before running the `docker-compose` command, the `docker-compose.yml` file should be configured. By default, the `docker-compose.yml` file is using environment variables available in the file `.env.sample`.

You can either rename the file `.env.sample` as `.env` and enter the values or just directly edit the `docker-compose.yml` with the values for your environment.

!!! note "Configuration static parameters"

    The complete list of available static parameters is available in the [configuration](configuration.md) section.

Here is an example to quickly generate the `.env` file on Linux, including all default UUIDv4 values:

```bash
sudo apt install -y jq
cd ~/docker
(cat << EOF
###########################
# DEPENDENCIES            #
###########################

MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=$(openssl rand -base64 32)
SMTP_HOSTNAME=localhost
OPENSEARCH_ADMIN_PASSWORD=changeme
ELASTIC_MEMORY_SIZE=4G

###########################
# COMMON                  #
###########################

XTM_COMPOSER_ID=8215614c-7139-422e-b825-b20fd2a13a23
COMPOSE_PROJECT_NAME=xtm

###########################
# OPENCTI                 #
###########################

OPENCTI_HOST=localhost
OPENCTI_PORT=8080
OPENCTI_EXTERNAL_SCHEME=http
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMePlease
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(cat /proc/sys/kernel/random/uuid)
OPENCTI_ENCRYPTION_KEY=$(openssl rand -base64 32)

###########################
# OPENCTI CONNECTORS      #
###########################

CONNECTOR_EXPORT_FILE_STIX_ID=dd817c8b-abae-460a-9ebc-97b1551e70e6
CONNECTOR_EXPORT_FILE_CSV_ID=7ba187fb-fde8-4063-92b5-c3da34060dd7
CONNECTOR_EXPORT_FILE_TXT_ID=ca715d9c-bd64-4351-91db-33a8d728a58b
CONNECTOR_IMPORT_FILE_STIX_ID=72327164-0b35-482b-b5d6-a5a3f76b845f
CONNECTOR_IMPORT_DOCUMENT_ID=c3970f8a-ce4b-4497-a381-20b7256f56f0
CONNECTOR_IMPORT_FILE_YARA_ID=7eb45b60-069b-4f7f-83a2-df4d6891d5ec
CONNECTOR_IMPORT_EXTERNAL_REFERENCE_ID=d52dcbc8-fa06-42c7-bbc2-044948c87024
CONNECTOR_ANALYSIS_ID=4dffd77c-ec11-4abe-bca7-fd997f79fa36

###########################
# OPENCTI DEFAULT DATA    #
###########################

CONNECTOR_OPENCTI_ID=dd010812-9027-4726-bf7b-4936979955ae
CONNECTOR_MITRE_ID=8307ea1e-9356-408c-a510-2d7f8b28a0e2
EOF
) > .env
```

If your `docker compose` deployment does not support `.env` files, just export all environment variables before launching the platform:

```bash
export $(cat .env | grep -v "#" | xargs)
```

As OpenCTI has a dependency on ElasticSearch, you have to set `vm.max_map_count` before running the containers, as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
sudo sysctl -w vm.max_map_count=1048575
```

To make this parameter persistent, add the following at the end of your `/etc/sysctl.conf`:

```bash
vm.max_map_count=1048575
```


### Persist data

The default for OpenCTI data is to be persistent.

In `docker-compose.yml`, you will find the list of necessary persistent volumes for the dependencies at the end:

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
sudo systemctl start docker.service
# Run docker-compose in detached
sudo docker compose up -d
```

#### Using Docker swarm

In order to have the best experience with Docker, we recommend using the Docker stack feature. In this mode you will have the capacity to easily scale your deployment.

```bash
# If your virtual machine is not a part of a Swarm cluster, please use:
sudo docker swarm init
```

Put your environment variables in `/etc/environment`:

```bash
# If you already exported your variables to .env from above:
sudo cat .env >> /etc/environment
sudo bash -c 'cat .env >> /etc/environment'
sudo docker stack deploy --compose-file docker-compose.yml opencti
```

!!! success "Installation done"

    You can now go to [http://localhost:8080](http://localhost:8080/) and log in with the credentials configured in your environment variables.

## Manual installation

### Prerequisites

#### Installation of dependencies

You have to install all the needed dependencies for the main application and the workers. The example below is for Debian-based systems:

```bash
sudo apt-get update
sudo apt-get install build-essential nodejs npm python3 python3-pip python3-dev
```

#### Download the application files

First, you have to [download and extract the latest release file](https://github.com/OpenCTI-Platform/opencti/releases). Then select the version to install depending on your operating system:

**For Linux:**

- If your OS supports libc (Ubuntu, Debian, ...) you have to install the `opencti-release_{RELEASE_VERSION}.tar.gz` version.
- If your OS uses musl (Alpine, ...) you have to install the `opencti-release-{RELEASE_VERSION}_musl.tar.gz` version.

**For Windows:**

We currently don't provide any Windows release. However, it is still possible to check-out the code, manually install the dependencies and build the software.

```bash
mkdir /path/to/your/app && cd /path/to/your/app
wget <https://github.com/OpenCTI-Platform/opencti/releases/download/{RELEASE_VERSION}/opencti-release-{RELEASE_VERSION}.tar.gz>
tar xvfz opencti-release-{RELEASE_VERSION}.tar.gz
```

### Install the platform core

#### Configure the application

The main application has just one JSON configuration file to change and a few Python modules to install.

```bash
cd opencti
cp config/default.json config/production.json
```

Change the *config/production.json* file according to your configuration of ElasticSearch, Redis, RabbitMQ and S3 bucket as well as default credentials (the `ADMIN_TOKEN` must be a [valid UUID](https://www.uuidgenerator.net/)).

#### Install the Python modules

```bash
cd src/python
pip3 install -r requirements.txt
cd ../..
```

#### Start the application

The application is a single NodeJS process. The creation of the database schema and potential data migrations happen during startup.

> Please verify Node.js version is greater than or equal to v20, and that corepack is installed.
> Please note that some Node.js versions are outdated in linux package managers. You can download a recent one at https://nodejs.org/en/download. Alternatively, consider using nvm (https://github.com/nvm-sh/nvm) to help pick a recent version of Node.js.
> To install corepack, execute the following command after the installation of Node.js: `npm install -g corepack`

```bash
node --version
#v20.11.1
corepack --version
#0.34.0
```

Once Node.js is set up, you can build and run the application with (from inside `opencti` folder):

```bash
yarn install
yarn build
yarn serv
```

The default username and password are those you have set in the `config/production.json` file.

### Install the worker

The OpenCTI worker is used to write the data coming from the RabbitMQ message brokers.

#### Configure the worker

```bash
cd worker
pip3 install -r requirements.txt
cp config.yml.sample config.yml
```

Change the *config.yml* file according to your OpenCTI token.

#### Start as many workers as you need

```bash
python3 worker.py &
python3 worker.py &
```

!!! success "Installation done"

    You can now go to [http://localhost:4000](http://localhost:4000) and log in with the credentials configured in your `production.json` file.

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

    OpenCTI Helm Charts for Kubernetes with a global configuration file. More information how to deploy here on [basic installation](https://github.com/devops-ia/helm-opencti/blob/main/charts/opencti/docs/configuration.md) and [examples](https://github.com/devops-ia/helm-opencti/blob/main/charts/opencti/docs/examples.md).

    [:material-github:{ .middle } GitHub Repository](https://github.com/devops-ia/helm-opencti/tree/main/charts/opencti)
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

OpenCTI workers and connectors are Python processes. If you want to limit the memory of the process, we recommend directly using Docker to do that. You can find more information in the [official Docker documentation](https://docs.docker.com/compose/compose-file/).

#### ElasticSearch

ElasticSearch is also a JAVA process. In order to set up the JAVA memory allocation, you can use the `ES_JAVA_OPTS` environment variable. You can find more information in the [official ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html).

#### Redis

Redis has a very small footprint on keys but will consume memory for the stream. By default, the size of the stream is limited to 2 million which represents a memory footprint of about `8 GB`. You can find more information in the [Redis docker hub](https://hub.docker.com/_/redis).

#### MinIO / S3 Bucket

MinIO is a small process and does not require a high amount of memory. More information is available for Linux in the [Kernel tuning guide](https://github.com/minio/minio/tree/master/docs/deployment/kernel-tuning).

#### RabbitMQ

The RabbitMQ memory configuration can be found in the [official RabbitMQ documentation](https://www.rabbitmq.com/memory.html). RabbitMQ will consume memory until it reaches a specific threshold, so it should be configured in alignment with Docker's memory limitations.

# Installation

## Using Docker

### Introduction

OpenCTI can be deployed using the *docker-compose* command.

!!! info "Memory management"

    For production deployment, we advise you to deploy ElasticSearch and Redis manually in a dedicated environment and then to start the other components using Docker.

## 1. Pre-requisites

****🐧 Linux:****

```bash
$ sudo apt-get install docker-compose
```

**⌘ MacOS**

Download: [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)

## 2. Clone the repository

```bash
$ mkdir -p /path/to/your/app && cd /path/to/your/app
$ git clone https://github.com/OpenCTI-Platform/docker.git
$ cd docker
```

## 3. Configure the environment

Before running the `docker-compose` command, the `docker-compose.yml` file must be configured.

There are two ways to do that:

1. Use environment variables as it is proposed and you have an exemple in the `.env.sample` file (ie. `APP__ADMIN__EMAIL=${OPENCTI_ADMIN_EMAIL}`).
2. Directly set the parameters in the `docker-compose.yml`.

If setting within the environment, you can reference the methodology in the [Environment setup on OpenCTI's Notion page](https://www.notion.so/Environment-setup-606996f36d904fcf8d434c6d0eae4a00) - located below for ease:

### **🐧 Linux:**

```bash
sudo apt install -y jq

cd ~/docker
(cat << EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=CHANGEMEPLEASE
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_REPORT_ID=$(cat /proc/sys/kernel/random/uuid)
EOF
 ) > .env
```

### **⌘ MacOS**

```bash
brew install jq
cd ~/docker
 (cat <<EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=CHANGEMEPLEASE
OPENCTI_ADMIN_TOKEN=$(uuidgen)
MINIO_ROOT_USER=$(uuidgen)
MINIO_ROOT_PASSWORD=$(uuidgen)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
CONNECTOR_HISTORY_ID=$(uuidgen)
CONNECTOR_EXPORT_FILE_STIX_ID=$(uuidgen)
CONNECTOR_EXPORT_FILE_CSV_ID=$(uuidgen)
CONNECTOR_IMPORT_FILE_STIX_ID=$(uuidgen)
CONNECTOR_IMPORT_REPORT_ID=$(uuidgen)
EOF
) > .env
```

```bash
cd ~/docker 
# trick to export the .env 
export $(cat .env | grep -v "#" | xargs)
```

## **4. Memory Management Settings**

<aside>
💡 For additional memory management information see the Memory configuration notes section

</aside>

As OpenCTI has a dependency on ElasticSearch, you have to set the `vm.max_map_count` before running the containers, as mentioned in the [ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html#docker-cli-run-prod-mode).

```bash
$ sudo sysctl -w vm.max_map_count=1048575
```

To make this parameter persistent, add the following to the end of your `/etc/sysctl.conf`:

```bash
$ vm.max_map_count=1048575
```

## **5. Run OpenCTI - Full-stack, including UI**

### Using single node Docker

### Using Docker swarm

After changing your `.env` file run `docker-compose` in detached (`-d`) mode:

In order to have the best experience with Docker, we recommend using the Docker stack feature. In this mode you will have the capacity to easily scale your deployment. 

<aside>
💡 **Top Tip:** If you are looking for a easy way to manage your docker installation and containers try [Portainer](https://documentation.portainer.io/quickstart/?hsCtaTracking=cb3a059b-7f57-4333-a92f-b06202ef8690%7C4427d7bc-1ae8-4a30-812c-d30ee496008f).

</aside>

```bash
# ****🐧**** Linux only
$ sudo systemctl start docker.service
# Run docker-compose in detached 
$ docker-compose up -d
```

```bash
# If your virtual machine is not a part of a Swarm cluster, please use:
$ docker swarm init
```

Put your environment variables in `/etc/environment`:

```bash
# If you already exported your variables to .env from above:
$ sudo cat .env >> /etc/environment
$ sudo bash -c 'cat .env >> /etc/environment’
$ sudo docker stack deploy --compose-file docker-compose.yml opencti
```

You can now go to [http://localhost:8080](http://localhost:8080/) and log in with the credentials configured in your environment variables.

## **6. Run OpenCTI infrastructure with UI/GraphQL in development mode**

In order to develop OpenCTI UI/GraphQL in the most efficient manner we have provided a `docker-compose.dev.yml` which stands up the back-end/infrastructure of OpenCTI, with the expectation that you will run the OpenCTI front-end (React/GraphQL) separately.

This docker-compose exposes all necessary ports for the UI/GraphQL to attach to in order to support local development.

To run the services required for local development run:

```bash
$ sudo docker-compose -f docker-compose.dev.yml up -d
```

To configure/run the UI/GraphQL we would direct you to the [Notion documentation](https://www.notion.so/Front-end-e4991302301b438cad9567fc9e9e3b89)

# **Appendices**

## **A. How to update your docker instances**

### **For single node Docker**

```bash
$ sudo docker-compose stop
$ sudo docker-compose pull
$ sudo docker-compose up -d
```

### **For Docker swarm**

For each of services, you have to run the following command:

```bash
$ sudo docker service update --force service_name
```

## **B. How to deploy behind a reverse proxy**

If you want to use OpenCTI behind a reverse proxy with a context path, like `https://myproxy.com/opencti`, please change the base_path configuration.

- `APP__BASE_PATH=/opencti`

By default OpenCTI use websockets so don't forget to configure your proxy for this usage, an example with `Nginx`:

```bash
location / {
    proxy_cache               off;
    proxy_buffering           off;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    chunked_transfer_encoding off;
    proxy_pass http:/YOUR_UPSTREA_BACKEND;
  }
```

## **C. How to persist data**

The default for OpenCTI data is to be persistent.

If you do not wish the data to persist:

```bash
$ mv docker-compose.override.no-persist.yml docker-compose.override.yml
```

---

## **D. Memory configuration: additional information**

### OpenCTI - Platform

OpenCTI platform is based on a NodeJS runtime, with a memory limit of **8GB by default**. If you encounter `OutOfMemory` exceptions, this limit could be changed:

```yaml
- NODE_OPTIONS=--max-old-space-size=8096
```

### OpenCTI - Workers and connectors

OpenCTI workers and connectors are Python processes. If you want to limit the memory of the process, we recommend to directly use Docker to do that. You can find more information in the [official Docker documentation](https://docs.docker.com/compose/compose-file/).

<aside>
💡 If you do not use Docker stack, consider using the `--compatibility` option.

</aside>

### ElasticSearch

ElasticSearch is also a JAVA process. In order to setup the JAVA memory allocation, you can use the environment variable `ES_JAVA_OPTS`.

<aside>
💡 The minimal recommended option today is `-Xms8G -Xmx8G`

</aside>

You can find more information in the [official ElasticSearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html).

### Redis

Redis has a very small footprint on keys but will consume memory for the stream. By default the size of the stream is limited to 2 millions

<aside>
💡 With 2 million of events in the stream, the memory footprint will be around `8G`

</aside>

You can find more information in the [Redis docker hub](https://hub.docker.com/r/bitnami/redis/).

### MinIO

MinIO is a small process and does not require a high amount of memory. More information are available for Linux here on the [Kernel tuning guide](https://github.com/minio/minio/tree/master/docs/deployment/kernel-tuning).

### RabbitMQ

The RabbitMQ memory configuration can be find in the [RabbitMQ official documentation](https://www.rabbitmq.com/memory.html). RabbitMQ will consumed memory until a specific threshold, therefore it should be configure along with the Docker memory limitation.

## E. Load-balancing

Ingesting lots of data from connectors can cause the OpenCTI platform to slow down and make it difficult for analysts to use the platform properly for their work. A simple way of solving this issue is to have 2 parallel OpenCTI platform containers running at the same time and to distribute the workload between them.

1. OpenCTI container #1 is the responsible go-to address for all connectors for ingesting data
2. OpenCTI container #2 is the analysts’ UI interface for their research

Since both OpenCTI containers are using the same backend infrastructure, both platforms are able to access the same data while balancing the workload between them.

## F. Updating OpenCTI containers

Before applying this procedure, please update your `docker-compose.yml` file with the new version number of container images.

### Using single node Docker

### Using Docker swarm

```bash
$ docker-compose up -d
```

For each of services, you have to run the following command:

```bash
$ docker service update --force service_name
```

## G. Deployment behind a reverse proxy

If you want to use OpenCTI behind a reverse proxy with a context path, like `https://myproxy.com/opencti`, please change the `base_path` configuration.

```yaml
- APP__BASE_PATH=/opencti
```

By default OpenCTI use websockets and SSE so don't forget to configure your proxy for this usage, an example with `Nginx`:

```bash
location / {
    proxy_cache               off;
    proxy_buffering           off;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    chunked_transfer_encoding off;
    proxy_pass http://YOUR_UPSTREAM_BACKEND;
  }
```

# Community Additions

## Setup with Caddy Server (thanks to @[sukesh-ak](https://github.com/sukesh-ak))

Setup and automate **FREE** valid SSL for OpenCTI, using an OpenSource project called [Caddy Server](https://caddyserver.com/) with very minimal effort.

### **About Caddy**

Caddy 2 is a powerful, enterprise-ready, open source web server with **automatic HTTPS** written in Go. Caddy works well as a direct install and also using Docker.

### **Using Docker**

OpenCTI runs all its components in individual containers. For accessing the WebUI, by default it exposes opencti service on port 8080 locally.

It’s easy to setup reverse proxy with FREE SSL using Caddy with very minimal effort. So lets check the steps for setting it up

- Configure DNS with A record pointing to your OpenCTI public IP address
- Create a base folder for config file `'Caddyfile'`
- Create a `docker-compose` file for Caddy
- Create a container using `docker-compose run`

```bash
# Create a DNS A/AAAA record pointing your domain to the public IP address
$ cti.domain.com  A  <public-IP-address-for-OpenCTI-instance>
```

Make sure to wait for the DNS record to complete propagation (depending on TTL). Otherwise automatic SSL creation would not work.

Caddy uses 2 volumes for data (storing certificates etc) & config.Create a file called `'Caddyfile'` in the local folder for configuration, which will be mapped to `/etc/caddy/Caddyfile` through docker-compose file as below.

```bash
# /etc/caddy/Caddyfile
cti.domain.com {
	reverse_proxy http://opencti:8080
}
```

<aside>
💡 Port 80 mapping is not necessary but it helps in automatic redirection if clients try the HTTP url.

</aside>

```bash
# **docker-compose-caddy.yml** 
 version: "3.7"
	services:
	  caddy:
	    image: caddy
	    restart: unless-stopped
	    ports:
	      - "80:80"
	      - "443:443"
			volumes:
	      - ./Caddyfile:/etc/caddy/Caddyfile
	      - caddy_data:/data
	      - caddy_config:/config

networks:
  default:
    external: true
    name: <your OpenCTI network name>
    
volumes:
  caddy_data:
  caddy_config:
```

Since you are running Caddy in docker, you need to make it part of OpenCTI network. Reverse proxy takes care of everything else. This also means you don't need to expose OpenCTI `8080` port outside the container. So you can remove `-port` setting in OpenCTI `docker-compose` file.

Now just get it running and Caddy will request and get SSL certificate automagically for your domain.

```bash
docker-compose -f docker-compose-caddy.yml up -d
```

### **Resources**

How Caddy automatic SSL works [https://caddyserver.com/docs/automatic-https](https://caddyserver.com/docs/automatic-https)

Using Caddy with Load Balancer [https://caddy.community/t/load-balancing-caddy/10467](https://caddy.community/t/load-balancing-caddy/10467)
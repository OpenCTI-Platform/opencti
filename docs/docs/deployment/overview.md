# Overview

Before starting the installation, let's discover how OpenCTI works, which dependencies are needed and what are the minimum requirements for deploying it in production.

!!! tip "Docker deployment of the full XTM suite (OpenCTI - OpenAEV - OpenGRC)"

    If you're looking for information about the deployment of the full eXtended Threat Management (XTM) suite using Docker, please refer [to this repository and documentation](https://github.com/FiligranHQ/xtm-docker).

## Architecture

The OpenCTI platform is mainly composed of three distinct parts to handle the flow of data: the core, the connectors and the workers.
It also relies on several third party storage, databases and messaging systems in order to operate.

![Architecture](assets/architecture.png)

### Core

The platform core is the central part of the OpenCTI technological stack. It allows users to access the user interface but also provides the [GraphQL API](https://graphql.org) used by connectors and workers to insert data. In the context of a production deployment, you may need to scale horizontally and launch multiple cores behind a load balancer connected to the same databases, storage & messaging components (ElasticSearch, Redis, S3, RabbitMQ).

### Workers

The workers are standalone Python processes consuming messages from the RabbitMQ broker in order to execute asynchronous write operations. You can launch as many workers as needed to increase write performance. At some point, the write performance will be limited by the throughput of the ElasticSearch database cluster.

!!! note "Number of workers"

    If you need to increase performance, it is better to spawn more core instances to handle worker queries. The recommended setup is to have at least one core running for 3 workers (ie. 9 workers distributed over 3 cores).

### Connectors

The connectors are third-party pieces of software (Python processes) that can play five different 
roles on the platform:

| Type                 | Description                                                                                               | Examples                                              |
|:---------------------|:----------------------------------------------------------------------------------------------------------|:------------------------------------------------------|
| EXTERNAL_IMPORT      | Pull data from remote sources, convert it to STIX2, and insert it into the OpenCTI platform.              | MITRE Datasets, MISP, CVE, AlienVault, Mandiant, etc. |
| INTERNAL_ENRICHMENT  | Listen for new OpenCTI entities or users requests and pull data from remote sources to enrich them.       | Shodan, DomainTools, IpInfo, etc.                     |
| INTERNAL_IMPORT_FILE | [Extract data from files](../usage/import-files.md) uploaded on OpenCTI through the UI or the API.        | STIX 2.1, PDF, Text, HTML, etc.                       |
| INTERNAL_EXPORT_FILE | [Generate an export](../usage/export.md) from OpenCTI data based on a single object or a list of objects. | STIX 2.1, CSV, PDF, etc.                              |
| STREAM               | Consume a [data stream](../usage/feeds.md) produced by the platform and process the events at will.       | Splunk, Elastic Security, Q-Radar, etc.               |

!!! note "List of connectors"
    
    You can find all currently available connectors in the [XTM Hub Integrations Library](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations).

## Infrastructure requirements

### Dependencies

| Component                  | Version            | CPU       | RAM          | Disk type                    | Disk space      |
|:---------------------------|:-------------------|:----------| :----------- | :--------------------------- | :-------------- |
| ElasticSearch / OpenSearch | >= 8.0 / >= 2.9    | 2 cores   | ≥ 8GB        | SSD                          | ≥ 16GB          |
| Redis                      | >= 7.1             | 1 core    | ≥ 1GB        | SSD                          | ≥ 16GB          |
| RabbitMQ                   | >= 3.11            | 1 core    | ≥ 512MB      | Standard                     | ≥ 2GB           |
| S3 / MinIO                 | >= RELEASE.2023-02 | 1 core    | ≥ 128MB      | SSD                          | ≥ 16GB          |


### Platform

| Component        | CPU         | RAM          | Disk type                         | Disk space      |
| :--------------- | :---------- | :----------- | :-------------------------------- | :-------------- |
| OpenCTI Core     | 2 cores     | ≥ 8GB        | None (stateless)                  | -               |
| Worker(s)        | 1 core      | ≥ 128MB      | None (stateless)                  | -               |
| Connector(s)     | 1 core      | ≥ 128MB      | None (stateless)                  | -               |
| XTM composer     | 1 core      | ≥ 128MB      | None (stateless)                  | -               |

!!! note "Clustering"
    
    To have more details about deploying OpenCTI and its dependencies in cluster mode, please read the [dedicated section](clustering.md).

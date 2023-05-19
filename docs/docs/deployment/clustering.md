# Clustering

## Introduction

The OpenCTI platform technological stack has been designed to be able to scale horizontally. All dependencies such as Elastic or Redis can be deployed in cluster mode and performances can be drastically increased by deploying multiple platform and worker instances.

## High level architecture

Here is the high level architecture for customers and Filigran cloud platform to ensure both high availability and throughput.

![Cluster](assets/cluster.png)

## Configuration

### Dependencies

#### ElasticSearch

In the ElasticSearch configuration of OpenCTI, it is possible to declare all nodes.

```yaml
- "ELASTICSEARCH__URL=[\"https://user:pass@node1:9200\", \"https://user:pass@node2:9200\", ...]"
```

!!! note "Compatibility"
    
    OpenCTI is also compatible with OpenSearch and AWS / GCP / Azure native search services based on the ElasticSearch query language.

#### Redis

Redis should be turned to cluster mode:

```yaml
- REDIS__MODE=cluster
- "REDIS__HOSTNAMES=[\"node1:6379\", \"node2:6379\", ...]"
```

!!! note "Compatibility"
    
    OpenCTI is also compatible with ElastiCache, MemoryStore and AWS / GCP / Azure native services based on the Redis protocol.

#### RabbitMQ

For the RabbitMQ cluster, you will need a TCP load balancer on top of the nodes since the configuration does not support multi-nodes for now:

```yaml
- RABBITMQ__HOSTNAME=load-balancer-rabbitmq
```

!!! note "Compatibility"
    
    OpenCTI is also compatible with Amazon MQ, CloudAMQP and AWS / GCP / Azure native services based on the AMQP protocol.

#### S3 bucket / MinIO

MinIO is an open source server able to serve S3 buckets. It can be deployed in cluster mode and is compatible with several storage backend. OpenCTI is compatible with any tool following the S3 standard.

## Platform

As showed on the schema, best practices for cluster mode and to avoid any congestion in the technological stack are:

* Deploy platform(s) dedicated to end users and connectors registration
* Deploy platform(s) dedicated to workers / ingestion process
	* We recommend 3 to 4 workers maxiumum by OpenCTI instance.
	* The ingestion platforms will never be accessed directly by end users.

When enabling clustering, the number of nodes is displayed in Settings > Parameters.

![Cluster mode](assets/cluster-mode.png)

### Managers and schedulers

Also, since some managers like the rule engine, the task manager and the notification manager can take some resources in the OpenCTI NodeJS process, it is highly recommended to disable them in the frontend cluster. OpenCTI automatically handle the distribution and the launching of the engines across all nodes in the cluster except where they are explicitely [disabled in the configuration](configuration.md#schedules-engines).
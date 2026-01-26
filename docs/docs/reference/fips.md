# SSL FIPS 140-2 deployment

## Introduction

For organizations that need to deploy OpenCTI in a SSL FIPS 140-2 compliant environment, we provide FIPS compliant OpenCTI images for all components of the platform. Please note that you will also need to deploy dependencies (ElasticSearch / OpenSearch, Redis, etc.) with FIPS 140-2 SSL to have the full compliant OpenCTI technological stack.

!!! note "OpenCTI SSL FIPS 140-2 compliant builds"

    The OpenCTI platform, workers and connectors SSL FIPS 140-2 compliant images are based on packaged [Alpine Linux with OpenSSL 3 and FIPS mode enabled](https://github.com/FiligranHQ/docker-python-nodejs-fips) maintened by the Filigran engineering team.

## Dependencies

### AWS Native Services in FedRAMP compliant environment

It is important to remind that OpenCTI is fully compatible with AWS native services and all dependencies are available in both [FedRAMP Moderate (East / West)](https://aws.amazon.com/compliance/services-in-scope/FedRAMP/) and [FedRAMP High (GovCloud)](https://aws.amazon.com/compliance/services-in-scope/FedRAMP/) scopes.

* Amazon OpenSearch Service (OpenSearch)
* Amazon ElastiCache (Redis)
* Amazon MQ (RabbitMQ)
* Amazon Simple Storage Service (S3 bucket)

### ElasticSearch / OpenSearch

ElasticSearch is known to be compatible with FIPS 140-2 SSL using the proper JVM. There is a [comprehensive guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/fips-140-compliance.html) in the Elastic documentation.

Alternatively, please note that Elastic is also providing an [ElasticSearch FedRAMP authorized cloud offering](https://www.elastic.co/industries/public-sector/fedramp).  

### Redis

Redis does not provide FIPS 140-2 SSL compliant Docker images but supports very well custom [tls-ciphersuites](https://github.com/redis/redis/issues/7802) that can be configured to use the system FIPS 140-2 OpenSSL library. 

Alternatively, you can use a [Stunnel](https://www.stunnel.org/) TLS endpoint to ensure encrypted communication between OpenCTI and Redis. There are a few examples available, [here](https://github.com/kientv/redis-stunnel) or [here](https://github.com/Runnable/redis-stunnel).

### RabbitMQ

RabbitMQ does not provide FIPS 140-2 SSL compliant Docker images but, as Redis, supports [custom cipher suites](https://www.rabbitmq.com/docs/ssl#cipher-suites). Also, it is confirmed since RabbitMQ version 3.12.5, the associated Erlang build (> 26.1), [supports FIPS mode on OpenSSL 3](https://www.rabbitmq.com/docs/which-erlang).

Alternatively, you can use a [Stunnel](https://www.stunnel.org/) TLS endpoint to ensure encrypted communication between OpenCTI and RabbitMQ.

### S3 Bucket / MinIO

If you cannot use an S3 endpoint already deployed in your FIPS 140-2 SSL compliant environment, MinIO provides [FIPS 140-2 SSL compliant Docker images](https://hub.docker.com/r/minio/minio/tags?page=1&name=fips) which then are very easy to deploy within your environment.

## OpenCTI stack

### Platform

For the platform, we provide [FIPS 140-2 SSL compliant Docker images](https://hub.docker.com/r/opencti/platform/tags?page=1&name=fips). Just use the appropriate tag to ensure you are deploying the FIPS compliant version and follow the [standard Docker deployment](../deployment/installation.md) procedure. 

### Worker

For the worker, we provide [FIPS 140-2 SSL compliant Docker images](https://hub.docker.com/r/opencti/worker/tags?page=1&name=fips). Just use the appropriate tag to ensure you are deploying the FIPS compliant version and follow the [standard Docker deployment](../deployment/installation.md) procedure.

### Connectors

All connectors have FIPS 140-2 SSL compliant Docker images. For each connector you need to deploy, please use the tag `{version}-fips` instead of `{version}` and  follow the [standard deployment](../deployment/connectors.md) procedure. An example is available on [Docker Hub](https://hub.docker.com/r/opencti/connector-export-file-stix/tags?page=1&name=fips). 
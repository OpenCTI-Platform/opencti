# FIPS 140-3 deployment

## Introduction

For organizations that need to deploy OpenCTI in a FIPS 140-3 compliant environment, we provide FIPS 140-3 compliant OpenCTI images for all components of the platform. Please note that you will also need to deploy the dependencies (ElasticSearch / OpenSearch, Redis, etc.) with FIPS 140-3 compliant cryptography to have a fully compliant OpenCTI technological stack.

!!! note "OpenCTI FIPS 140-3 compliant builds"

    The OpenCTI platform, workers and connectors FIPS 140-3 compliant images are based on [Alpine Linux with the OpenSSL FIPS provider enabled](https://github.com/FiligranHQ/docker-python-nodejs-fips), maintained by the Filigran engineering team.

## Compliance posture

All cryptography in the OpenCTI FIPS 140-3 images goes through the **OpenSSL FIPS provider 3.1.2**, the module validated under **CMVP certificate #4985**, valid until 10 March 2030. FIPS mode is active by default: no flag, environment variable or configuration step is required to deploy in it.

The module is built from the validated source distribution, unmodified, by the procedure documented in its Security Policy for integrators embedding the module in their own product, with integrity verification and the required self-tests enabled. Non-approved algorithms are refused rather than substituted.

The images therefore support these claims:

* They perform cryptography through the OpenSSL FIPS provider 3.1.2, validated under CMVP certificate #4985.
* The module is built from the validated source distribution, unmodified, by the procedure documented in its Security Policy, with integrity verification and self-tests enabled.
* FIPS mode is enforced: non-approved algorithms are refused, not substituted.

The full posture is described in [`FIPS.md`](https://github.com/FiligranHQ/docker-python-nodejs-fips/blob/main/FIPS.md), in the base image repository.

## Dependencies

### AWS Native Services in FedRAMP compliant environment

It is important to remind that OpenCTI is fully compatible with AWS native services and all dependencies are available in both [FedRAMP Moderate (East / West)](https://aws.amazon.com/compliance/services-in-scope/FedRAMP/) and [FedRAMP High (GovCloud)](https://aws.amazon.com/compliance/services-in-scope/FedRAMP/) scopes.

* Amazon OpenSearch Service (OpenSearch)
* Amazon ElastiCache (Redis)
* Amazon MQ (RabbitMQ)
* Amazon Simple Storage Service (S3 bucket)

### ElasticSearch / OpenSearch

ElasticSearch supports FIPS 140-3 from version 9.4, and from 8.19.15 in the 8.x line, using the Bouncy Castle FIPS 2.x libraries as the Java security provider. Earlier versions support FIPS 140-2 with the Bouncy Castle 1.x libraries. There is a [comprehensive guide](https://www.elastic.co/docs/deploy-manage/security/fips-es) in the Elastic documentation.

Alternatively, please note that Elastic is also providing an [ElasticSearch FedRAMP authorized cloud offering](https://www.elastic.co/industries/public-sector/fedramp).  

### Redis

Redis does not provide FIPS 140 compliant Docker images but supports very well custom [tls-ciphersuites](https://github.com/redis/redis/issues/7802) that can be configured to use the system OpenSSL library in FIPS mode. 

Alternatively, you can use a [Stunnel](https://www.stunnel.org/) TLS endpoint to ensure encrypted communication between OpenCTI and Redis. There are a few examples available, [here](https://github.com/kientv/redis-stunnel) or [here](https://github.com/Runnable/redis-stunnel).

### RabbitMQ

RabbitMQ does not provide FIPS 140 compliant Docker images but, as Redis, supports [custom cipher suites](https://www.rabbitmq.com/docs/ssl#cipher-suites). Also, it is confirmed since RabbitMQ version 3.12.5, the associated Erlang build (> 26.1), [supports FIPS mode on OpenSSL 3](https://www.rabbitmq.com/docs/which-erlang).

Alternatively, you can use a [Stunnel](https://www.stunnel.org/) TLS endpoint to ensure encrypted communication between OpenCTI and RabbitMQ.

### S3 Bucket / MinIO

If you cannot use an S3 endpoint already deployed in your FIPS 140 compliant environment, MinIO provides [FIPS 140 compliant Docker images](https://hub.docker.com/r/minio/minio/tags?page=1&name=fips) which then are very easy to deploy within your environment.

## OpenCTI stack

### Platform

For the platform, we provide [FIPS 140-3 compliant Docker images](https://hub.docker.com/r/opencti/platform/tags?page=1&name=fips). Just use the appropriate tag to ensure you are deploying the FIPS 140-3 compliant version and follow the [standard Docker deployment](../deployment/installation.md) procedure. 

### Worker

For the worker, we provide [FIPS 140-3 compliant Docker images](https://hub.docker.com/r/opencti/worker/tags?page=1&name=fips). Just use the appropriate tag to ensure you are deploying the FIPS 140-3 compliant version and follow the [standard Docker deployment](../deployment/installation.md) procedure.

### Connectors

All connectors have FIPS 140-3 compliant Docker images. For each connector you need to deploy, please use the tag `{version}-fips` instead of `{version}` and  follow the [standard deployment](../deployment/connectors.md) procedure. An example is available on [Docker Hub](https://hub.docker.com/r/opencti/connector-export-file-stix/tags?page=1&name=fips). 

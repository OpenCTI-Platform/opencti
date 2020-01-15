---
id: version-2.0.0-architecture
title: Architecture of the application
sidebar_label: Architecture
original_id: architecture
---

The OpenCTI platform relies on several external databases and services in order to work. 

![Architecture](assets/getting-started/architecture.png "Architecture")

## The GraphQL API

The API is the central part of the OpenCTI platorm, allowing the *clients* (including the *frontend*) to interact with the *databases* and the *brokers*. Built in NodeJS, it implements the [GraphQL](https://graphql.org/) query language. As the API has not a full documentation for the moment, you can explore the available methods and parameters through a GraphQL playground. An example is available on the [demonstration instance](https://demo.opencti.io/graphql).

## The workers

The workers are standalone Python processes that just consume messages from the RabbitMQ broker in order to do asynchroneous write queries. You can launch as many workers as you need to increase the write performances. Nevertheless, the Grakn database could have some problems with concurrent writing and fails on some operations.

## The connectors

The connectors are third-party softwares (Python processes) that can play 4 different roles on the platform:

- EXTERNAL_IMPORT: from remote sources to OpenCTI STIX2 (ie. MITRE, MISP, CVE, etc.)
- INTERNAL_IMPORT_FILE: from OpenCTI file system to OpenCTI STIX (ie. Extraction of observables from PDFs, STIX2 import, etc.)
- INTERNAL_ENRICHMENT: from OpenCTI STIX2 to OpenCTI STIX2 (ie. Enrichment of observables though external servies, entities updates, etc.)
- INTERNAL_EXPORT_FILE: from OpenCTI STIX2 to OpenCTI file system (ie. STIX2 export, PDF export, CSV list generation, etc.)


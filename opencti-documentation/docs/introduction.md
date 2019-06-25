---
id: introduction
title: Introduction
sidebar_label: Introduction
---

![](assets/introduction/logo.png)
---
OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge, investigations and indicators of compromise. OpenCTI can be integrated with other applications such as [Maltego](https://www.paterva.com/web7/buy/maltego-clients/maltego-ce.php), [MISP](https://www.misp-project.org/), [CORTEX](https://github.com/TheHive-Project/Cortex) and many other STIX2 compliant products. It has been designed as a modern web application including a GraphQL API and an UX oriented frontend.

![Screenshot](assets/introduction/screenshot.png "OpenCTI")

## Demonstration

If you wish to discover how the OpenCTI platform is working, a [demonstration instance](https://demo.opencti.io) is available and open to everyone. This instance is reset every nights and based on reference data maintened by the OpenCTI developers.

## Releases download

The releases are available on the [Github releases page](https://github.com/OpenCTI-Platform/opencti/releases). You can also access to the [rolling release package](https://releases.opencti.io) generated from the mater branch of the repository.

## Installation

* [Use Docker](installation/docker.md) / Prefered way
* [Install OpenCTI manually](installation/manual.md)

## Development

Everything you need to be ready for helping the openCTI development can be find here:
* [Install OpenCTI for development](development/docker.md)


## Details

### Architecture

![Architecture](assets/introduction/architecture.png "OpenCTI architecture")

### Database visualizer

The [Grakn](https://github.com/graknlabs/grakn) knowledge graph database provides a client called the [Grakn workbase](https://github.com/graknlabs/workbase) that can be used to explore the whole database. You can use it in order to explore your data in an original way.

![Grakn workbase](assets/introduction/workbase.png "OpenCTI architecture")

## Community

### Status & bugs

Currently OpenCTI is under heavy development, if you wish to report bugs or ask for new features, you can directly use the [Github issues module](https://github.com/OpenCTI-Platform/opencti/issues).

### Discussion

If you need support or you wish to engage a discussion about the OpenCTI platform, feel free to join us on our [Slack channel](https://slack.luatix.org). You can also send us an email to contact@opencti.io.

## About

OpenCTI is a product powered by the collaboration of the [French national cybersecurity agency (ANSSI)](https://ssi.gouv.fr), the [CERT-EU](https://cert.europa.eu) and the [Luatix](https://www.luatix.org) non-profit organization.

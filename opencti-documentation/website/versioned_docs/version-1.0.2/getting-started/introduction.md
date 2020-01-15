---
id: version-1.0.2-introduction
title: Introduction
sidebar_label: Introduction
original_id: introduction
---

![](assets/getting-started/logo.png)
---

OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables. It has been created in order to structure, store, organize and visualize technical and non-technical information about cyber threats.

The structuration of the data is performed using a knowledge schema based on the [STIX2 standards](https://oasis-open.github.io/cti-documentation/). It has been designed as a modern web application including a [GraphQL API](https://graphql.org) and an UX oriented frontend. Also, OpenCTI can be integrated with other tools and applications such as [MISP](https://github.com/MISP/MISP), [TheHive](https://github.com/TheHive-Project/TheHive), [MITRE ATT&CK](https://github.com/mitre/cti), etc.

![Screenshot](assets/getting-started/screenshot.png "OpenCTI")

## Objective

The goal is to create a comprehensive tool allowing users to capitalize technical (such as TTPs and observables) and non-technical information (such as suggested attribution, victimlogy etc.) while linking each piece of information to its primary source (a report, a MISP event, etc.), with features such as links between each information, first and last seen dates, levels of confidence etc. The tool is able to use the [MITRE ATT&CK framework](https://attack.mitre.org) (through a [dedicated connector](https://github.com/OpenCTI-Platform/connectors)) to help structure the data. The user can also chose to implement its own datasets.

Once data has been capitalized and processed by the analysts within OpenCTI, new relations [may be inferred](../reference/inferences) from existing ones to facilitate the understanding and the representation of this information. This allow the user to extract and leverage meaningful knowledge from the raw data.

OpenCTI not only allows [imports](../usage/import) but also [exports of data](../usage/export) under different formats (CSV, STIX2 bundles, etc.). [Connectors](https://github.com/OpenCTI-Platform/connectors) are currently developped to accelerate interactions between the tool and other platforms.

## Demonstration

If you wish to discover how the OpenCTI platform is working, a [demonstration instance](https://demo.opencti.io) is available and open to everyone. This instance is reset every night and is based on reference data maintened by the OpenCTI developers.

## Releases download

The releases are available on the [Github releases page](https://github.com/OpenCTI-Platform/opencti/releases). You can also access to the [rolling release package](https://releases.opencti.io) generated from the mater branch of the repository.

## Installation

You have 3 options to install the OpenCTI platform, depending of your needs:

* [Install with Docker](../installation/docker) (recommended)
* [Install manually](../installation/manual) 
* [Install for development](../development/installation)

## Community

### Status & bugs

Currently OpenCTI is under heavy development, if you wish to report bugs or ask for new features, you can directly use the [Github issues module](https://github.com/OpenCTI-Platform/opencti/issues).

### Discussion

If you need support or you wish to engage a discussion about the OpenCTI platform, feel free to join us on our [Slack channel](https://slack.luatix.org). You can also send us an email to contact@opencti.io.

## About

OpenCTI is a product powered by the collaboration of the [French national cybersecurity agency (ANSSI)](https://ssi.gouv.fr), the [CERT-EU](https://cert.europa.eu) and the [Luatix](https://www.luatix.org) non-profit organization.

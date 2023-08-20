<h1 align="center">
  <a href="https://www.opencti.io"><img src="https://www.filigran.io/wp-content/uploads/2023/08/opencti_github.png" alt="OpenCTI"></a>
</h1>
<p align="center">
  <a href="https://www.opencti.io" alt="Website"><img src="https://img.shields.io/badge/website-opencti.io-blue.svg" /></a>
  <a href="https://docs.opencti.io" alt="Documentation"><img src="https://img.shields.io/badge/documentation-latest-orange.svg" /></a>
  <a href="https://community.filigran.io" alt="Slack"><img src="https://img.shields.io/badge/slack-3K%2B%20members-4A154B" /></a>
  <a href="https://drone.filigran.io/OpenCTI-Platform/opencti"><img src="https://drone.filigran.io/api/badges/OpenCTI-Platform/opencti/status.svg" /></a>
  <a href="https://codecov.io/gh/OpenCTI-Platform/opencti"><img src="https://codecov.io/gh/OpenCTI-Platform/opencti/graph/badge.svg" /></a>
  <a href="https://deepscan.io/dashboard#view=project&tid=4926&pid=6716&bid=57311"><img src="https://deepscan.io/api/teams/4926/projects/6716/branches/57311/badge/grade.svg" alt="DeepScan grade"></a>
  <a href="https://renovatebot.com"><img src="https://img.shields.io/badge/renovate-enabled-brightgreen.svg" alt="DeepScan grade"></a>
  <a href="https://hub.docker.com/u/opencti" alt="Docker pulls"><img src="https://img.shields.io/docker/pulls/opencti/platform" /></a>
</p>

## Introduction

OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables. It has been created in order to structure, store, organize and visualize technical and non-technical information about cyber threats.

The structuration of the data is performed using a knowledge schema based on the [STIX2 standards](https://oasis-open.github.io/cti-documentation/). It has been designed as a modern web application including a [GraphQL API](https://graphql.org) and an UX oriented frontend. Also, OpenCTI can be integrated with other tools and applications such as [MISP](https://github.com/MISP/MISP), [TheHive](https://github.com/TheHive-Project/TheHive), [MITRE ATT&CK](https://github.com/mitre/cti), etc.

![Screenshot](https://www.filigran.io/wp-content/uploads/2022/08/dashboard.png "Screenshot")

## Objective

The goal is to create a comprehensive tool allowing users to capitalize technical (such as TTPs and observables) and non-technical information (such as suggested attribution, victimology etc.) while linking each piece of information to its primary source (a report, a MISP event, etc.), with features such as links between each information, first and last seen dates, levels of confidence, etc. The tool is able to use the [MITRE ATT&CK framework](https://attack.mitre.org) (through a [dedicated connector](https://github.com/OpenCTI-Platform/connectors)) to help structure the data. The user can also choose to implement their own datasets.

Once data has been capitalized and processed by the analysts within OpenCTI, new relations may be inferred from existing ones to facilitate the understanding and the representation of this information. This allows the user to extract and leverage meaningful knowledge from the raw data.

OpenCTI not only allows [imports](https://docs.opencti.io/latest/usage/import-export) but also [exports of data](https://docs.opencti.io/latest/usage/import-export) under different formats (CSV, STIX2 bundles, etc.). [Connectors](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76) are currently developed to accelerate interactions between the tool and other platforms.

## Editions of the platform

OpenCTI platform has 2 different editions: Community (CE) and Enterprise (EE). The purpose of the Enterprise Edition is to provide [additional and powerful features](https://www.filigran.io/en/solutions/offers/enterprise-editions) which require specific investments in research and development. You can enable the Enterprise Edition directly in the settings of the platform.

* OpenCTI Community Edition, licensed under the [Apache 2, Version 2.0 license](LICENSE).
* OpenCTI Enterprise Edition, licensed under the [Non-Commercial license](LICENSE).

To understand what OpenCTI Enterprise Edition brings in terms of features, just check the [Enterprise Editions page](https://www.filigran.io/en/solutions/offers/enterprise-editions) on the Filigran website. You can also try this edition by enabling it in the settings of the platform.

## Documentation and demonstration

If you want to know more on OpenCTI, you can read the [documentation on the tool](https://docs.opencti.io). If you wish to discover how the OpenCTI platform is working, a [demonstration instance](https://demo.opencti.io) is available and open to everyone. This instance is reset every night and is based on reference data maintained by the OpenCTI developers.

## Releases download

The releases are available on the [Github releases page](https://github.com/OpenCTI-Platform/opencti/releases). You can also access the [rolling release package](https://releases.opencti.io) generated from the master branch of the repository.

## Installation

All you need to install the OpenCTI platform can be found in the [official documentation](https://docs.opencti.io). For installation, you can:

* [Use Docker](https://docs.opencti.io/latest/deployment/installation/#using-docker)
* [Install manually](https://docs.opencti.io/latest/deployment/installation/#install-manually)
* [Use Terraform (community)](https://docs.opencti.io/latest/deployment/installation/#terraform)
* [Use Helm charts (community)](https://docs.opencti.io/latest/deployment/installation/#helm-charts)

## Contributing

### Code of Conduct

OpenCTI has adopted a [Code of Conduct](CODE_OF_CONDUCT.md) that we expect project participants to adhere to. Please read the [full text](CODE_OF_CONDUCT.md) so that you can understand what actions will and will not be tolerated.

### Contributing Guide

Read our [contributing guide](CONTRIBUTING.md) to learn about our development process, how to propose bugfixes and improvements, and how to build and test your changes to OpenCTI.

### Beginner friendly issues

To help you get you familiar with our contribution process, we have a list of [beginner friendly issues](https://github.com/OpenCTI-Platform/opencti/labels/beginner%20friendly%20issue) which are fairly easy to implement. This is a great place to get started.

### Development

If you want to actively help OpenCTI, we created a [dedicated documentation](https://docs.opencti.io/latest/development/environment) about the deployment of a development environment and how to start the source code modification.

## Community

### Status & bugs

Currently OpenCTI is under heavy development, if you wish to report bugs or ask for new features, you can directly use the [Github issues module](https://github.com/OpenCTI-Platform/opencti/issues).

### Discussion

If you need support or you wish to engage a discussion about the OpenCTI platform, feel free to join us on our [Slack channel](https://community.filigran.io). You can also send us an email to contact@opencti.io.

## About

### Authors

OpenCTI is a product designed and developed by the company [Filigran](https://www.filigran.io).

<a href="https://www.filigran.io" alt="Filigran"><img src="https://www.filigran.io/wp-content/uploads/2023/08/filigran_text_small.png" width="200" /></a>

### GDPR and the OpenCTI OpenStreetMap server

In order to provide OpenCTI users with cartography features, the platform uses a dedicated OpenStreetMap server (https://map.opencti.io). To monitor usage and adapt services performances, Filigran collects access log to this server (including IP addresses).

By using this server, you authorize Filigran to collect this information. Otherwise, you are free to deploy your own OpenStreetMap server and modify the platform configuration accordingly.

If you have started using the Filigran server and change your mind, you have the right to access, limit, rectify, erase and receive your data. To exercise your rights, please send your request to gdpr@opencti.io.

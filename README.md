<h1 align="center">
  <a href="https://www.opencti.io"><img src="https://opencti-platform.github.io/docs/assets/getting-started/logo.png" alt="OpenCTI"></a>
</h1>
<p align="center">
  <a href="https://www.opencti.io" alt="Website"><img src="https://img.shields.io/badge/website-opencti.io-blue.svg" /></a>
  <a href="https://opencti-platform.github.io/docs" alt="Documentation"><img src="https://img.shields.io/badge/Documentation-RTFM-orange.svg" /></a>
  <a href="https://slack.luatix.org" alt="Slack"><img src="https://slack.luatix.org/badge.svg" /></a>
  <a href="https://cloud.drone.io/OpenCTI-Platform/opencti"><img src="https://cloud.drone.io/api/badges/OpenCTI-Platform/opencti/status.svg?ref=refs/heads/issue/513" /></a>
  <a href="https://codecov.io/gh/OpenCTI-Platform/opencti"><img src="https://codecov.io/gh/OpenCTI-Platform/opencti/branch/issue%2F513/graph/badge.svg" /></a>
  <a href="https://deepscan.io/dashboard#view=project&tid=4926&pid=6716&bid=57311"><img src="https://deepscan.io/api/teams/4926/projects/6716/branches/57311/badge/grade.svg" alt="DeepScan grade"></a>
  <a href="https://github.com/OpenCTI-Platform/opencti/releases/latest" alt="Releases"><img src="https://img.shields.io/github/release/OpenCTI-Platform/opencti.svg" /></a>
  <a href="https://hub.docker.com/u/opencti" alt="Docker pulls"><img src="https://img.shields.io/docker/pulls/opencti/platform" /></a>
</p>


## Introduction

OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables. It has been created in order to structure, store, organize and visualize technical and non-technical information about cyber threats.

The structuration of the data is performed using a knowledge schema based on the [STIX2 standards](https://oasis-open.github.io/cti-documentation/). It has been designed as a modern web application including a [GraphQL API](https://graphql.org) and an UX oriented frontend. Also, OpenCTI can be integrated with other tools and applications such as [MISP](https://github.com/MISP/MISP), [TheHive](https://github.com/TheHive-Project/TheHive), [MITRE ATT&CK](https://github.com/mitre/cti), etc.

![Screenshot](https://opencti-platform.github.io/docs/assets/getting-started/screenshot.png "Screenshot")

## Objective

The goal is to create a comprehensive tool allowing users to capitalize technical (such as TTPs and observables) and non-technical information (such as suggested attribution, victimlogy etc.) while linking each piece of information to its primary source (a report, a MISP event, etc.), with features such as links between each information, first and last seen dates, levels of confidence etc. The tool is able to use the [MITRE ATT&CK framework](https://attack.mitre.org) (through a [dedicated connector](https://github.com/OpenCTI-Platform/connectors)) to help structure the data. The user can also chose to implement its own datasets.

Once data has been capitalized and processed by the analysts within OpenCTI, new relations [may be inferred](https://opencti-platform.github.io/docs/reference/inferences) from existing ones to facilitate the understanding and the representation of this information. This allow the user to extract and leverage meaningful knowledge from the raw data.

OpenCTI not only allows [imports](https://opencti-platform.github.io/docs/usage/import) but also [exports of data](https://opencti-platform.github.io/docs/usage/export) under different formats (CSV, STIX2 bundles, etc.). [Connectors](https://github.com/OpenCTI-Platform/connectors) are currently developped to accelerate interactions between the tool and other platforms.

## Documentation and demonstration

If you want to know more on OpenCTI, you can read the [documentation on the tool](https://opencti-platform.github.io/docs). If you wish to discover how the OpenCTI platform is working, a [demonstration instance](https://demo.opencti.io) is available and open to everyone. This instance is reset every night and is based on reference data maintened by the OpenCTI developers.

## Releases download

The releases are available on the [Github releases page](https://github.com/OpenCTI-Platform/opencti/releases). You can also access to the [rolling release package](https://releases.opencti.io) generated from the mater branch of the repository.

## Installation

All you need to install the OpenCTI platform can be found in the [official documentation](https://opencti-platform.github.io/docs). For installation, you can:

* [Use Docker](https://opencti-platform.github.io/docs/installation/docker) (recommended)
* [Install manually](https://opencti-platform.github.io/docs/installation/manual)

## Contributing

### Code of Conduct

OpenCTI has adopted a [Code of Conduct](CODE_OF_CONDUCT.md) that we expect project participants to adhere to. Please read the [full text](CODE_OF_CONDUCT.md) so that you can understand what actions will and will not be tolerated.

### Contributing Guide

Read our [contributing guide](CONTRIBUTING.md) to learn about our development process, how to propose bugfixes and improvements, and how to build and test your changes to OpenCTI.

### Beginner friendly issues

To help you get you familiar with our contribution process, we have a list of [beginner friendly issues](https://github.com/OpenCTI-Platform/opencti/labels/beginner%20friendly%20issue) which are fairly easy to implement. This is a great place to get started.

### Development

If you want to actively help OpenCTI, we created a [dedicated documentation](https://opencti-platform.github.io/docs/development/installation) about the deployment of a development environement and how to start the source code modification.

## Community

### Status & bugs

Currently OpenCTI is under heavy development, if you wish to report bugs or ask for new features, you can directly use the [Github issues module](https://github.com/OpenCTI-Platform/opencti/issues).

### Discussion

If you need support or you wish to engage a discussion about the OpenCTI platform, feel free to join us on our [Slack channel](https://slack.luatix.org). You can also send us an email to contact@opencti.io.

## About

OpenCTI is a product powered by the collaboration of the [French national cybersecurity agency (ANSSI)](https://ssi.gouv.fr), the [CERT-EU](https://cert.europa.eu) and the [Luatix](https://www.luatix.org) non-profit organization.

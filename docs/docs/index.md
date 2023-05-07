# OpenCTI Documentation Space

Welcome to the OpenCTI Documentation space. Here you will be able to find all documents, meeting notes and presentations about the platform.

## Introduction

OpenCTI is an open source platform allowing organizations to manage their cyber threat intelligence knowledge and observables. It has been created in order to structure, store, organize and visualize technical and non-technical information about cyber threats.

The structuration of the data is performed using a knowledge schema based on the [STIX2 standards](https://oasis-open.github.io/cti-documentation/). It has been designed as a modern web application including a [GraphQL API](https://graphql.org) and an UX oriented frontend. Also, OpenCTI can be integrated with other tools and applications such as [MISP](https://github.com/MISP/MISP), [TheHive](https://github.com/TheHive-Project/TheHive), [MITRE ATT&CK](https://github.com/mitre/cti), etc.

![Screenshot](https://www.opencti.io/wp-content/uploads/2022/02/screenshot.png "Screenshot")

## Objective

The goal is to create a comprehensive tool allowing users to capitalize technical (such as TTPs and observables) and non-technical information (such as suggested attribution, victimology etc.) while linking each piece of information to its primary source (a report, a MISP event, etc.), with features such as links between each information, first and last seen dates, levels of confidence, etc. The tool is able to use the [MITRE ATT&CK framework](https://attack.mitre.org) (through a [dedicated connector](https://github.com/OpenCTI-Platform/connectors)) to help structure the data. The user can also choose to implement their own datasets.

Once data has been capitalized and processed by the analysts within OpenCTI, new relations may be inferred from existing ones to facilitate the understanding and the representation of this information. This allows the user to extract and leverage meaningful knowledge from the raw data.

OpenCTI not only allows [imports](https://filigran.notion.site/Import-Export-7dc143dfbb6147b0881080487ed9db33#4ffd142e88ad489abc3370ea8f738a82) but also [exports of data](https://filigran.notion.site/Import-Export-7dc143dfbb6147b0881080487ed9db33#8dfec135e334415fb18f1f169fe89804) under different formats (CSV, STIX2 bundles, etc.). [Connectors](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76) are currently developed to accelerate interactions between the tool and other platforms.

## Editions of the platform

OpenCTI platform has 2 different editions: Community (CE) and Enterprise (EE). The purpose of the Enterprise Edition is to provide [additional and powerful features](https://www.filigran.io/en/solutions/offers/enterprise-editions) which require specific investments in research and development. You can enable the Enterprise Edition directly in the settings of the platform.

* OpenCTI Community Edition, licensed under the [Apache 2, Version 2.0 license](LICENSE).
* OpenCTI Enterprise Edition, licensed under the [Non-Commercial license](LICENSE).

To understand what OpenCTI Enterprise Edition brings in terms of features, just check the [Enterprise Editions page](https://www.filigran.io/en/solutions/offers/enterprise-editions) on the Filigran website. You can also try this edition by enabling it in the settings of the platform.

## About

### Authors

OpenCTI is a product designed and developed by the company [Filigran](https://www.filigran.io).

<a href="https://www.filigran.io" alt="Filigran"><img src="https://www.filigran.io/wp-content/uploads/2022/08/filigran_text_horizontal_dense_margin.png" width="230" /></a>
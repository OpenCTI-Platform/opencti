---
id: overview
title: Overview
sidebar_label: Overview
---

The following document presents some basic explanations on the different platform sections. Its goal is to allow a beginner with OpenCTI to navigate the tool efficiently. This is not a full-fledged user guide and therefore is incomplete. 

We are trying to make it evolve along with the platform but you may find some parts behind the lastest evolutions. If it is the case, please don't hesitate to open an [issue](https://github.com/OpenCTI-Platform/opencti/issues/new/choose).

## Sections of the platform

### Knowledge

When you open the platform, you find yourself on the dashboard. The dashboard will fill up progressively as you import data.

![Dashboard](assets/usage/dashboard.png "Dashboard")

On the left side, you can see a menu made of several icons. The upper left one is the one for the dashboard. The grey ones are services which are not yet implemented on the platform but which we are working on (if you are interested in contributing, you can start [here](https://github.com/OpenCTI-Platform/opencti/blob/master/CONTRIBUTING.md))

> The small arrow at the bottom left allows you to unroll the menu in order to see the name for each icon.

![Menu](assets/usage/menu.png "Menu")

Below the dashboard icon, the other icons are for the following services:

#### Threats

This service allows you to go through all the data in the platform organized by threat actors or intrusion sets or campaigns or incidents or malwares. Clicking on one of the matching tab in the upper part of the window allows the user to visualize all the knowledge on one of this entity.

![Intrusion Sets](assets/usage/intrusion_sets.png "Intrusion Sets")

#### Techniques

This tab allows the user to look among all the Techniques, Tactics and Procedures (TTPs) which may be used during an attack. This covers all the kill chain phases as detailed in the [MITRE ATT&CK framework](https://attack.mitre.org/) but also tools, vulnerabilities and identified courses of actions which can be implemented to block theses techniques.

![TTPs](assets/usage/ttps.png "TTPs")

#### Signatures

The signatures  tab contains all the technical observables and indicators which may have been seen during an attack, such as infrastructure or file hashes. Only a few categories are available today, but the list is bound to expand. If you wish to contribute to this part, click [here](https://github.com/OpenCTI-Platform/opencti/blob/master/CONTRIBUTING.md).

![Observables](assets/usage/observables.png "Observables")

#### Reports

In this tab are all the reports which have been uploaded to the platform. They will be the starting point for processing the data inside the reports. For more details, refer to the explanations on how [to upload a report](usage/usage-create-reports) and how [to analyze a report](usage/usage-analyze-report).

![Reports](assets/usage/reports.png "Reports")

#### Entities 

This tab contains all information organized according to the identified entities, which can be either sectors, regions, organisations etc. targeted by an attack or involved in it. Lists of entities can be synchronized from the [repository](https://github.com/OpenCTI-Platform/datasets) through the OpenCTI connector or can be created internally.

![Entities](assets/usage/entities.png "Entities")

### Exploration and processing

#### Explore

This tab is a bit specific, as it constitute a workspace from which the user can automatically generates graphs, timelines, charts and tables from the data previously processed. This can help compare victimologies, timelines of attacks etc. If you want to know more about this service, you can read the article on [how to use the Explore workspace](#usingtheexploreworkspace)

![Workspaces](assets/usage/workspaces.png "Workspaces")

####  Investigate

This service is currently under construction and will be available soon. If you are interested in contributing to its development, see [here](https://github.com/OpenCTI-Platform/opencti/blob/master/CONTRIBUTING.md).

#### Correlate

This service is currently under construction and will be available soon. If you are interested in contributing to its development, see [here](https://github.com/OpenCTI-Platform/opencti/blob/master/CONTRIBUTING.md).

### Parameters

#### Connectors

In this tab, you can manage the different connectors which are used to upload data to the platform. New connectors are being developed. If you are interested in helping or if you would like to have a connector for a specific service, see [the documentation for dcontributing](https://github.com/OpenCTI-Platform/opencti/blob/master/CONTRIBUTING.md) or [open a feature request](https://github.com/OpenCTI-Platform/opencti/tree/master/.github/ISSUE_TEMPLATE).

![Connectors](assets/usage/connectors.png "Connectors")

#### Settings

In this tab, you can change the parameters, visualize all users, create or manage groups, create or manage tagging (by default, the Traffic Light Protocol is implemented, but you can add your own tagging) and manage the kill chain steps (by default, the kill chainis the one defined in the [MITRE ATT&CK framework](https://attack.mitre.org/)).
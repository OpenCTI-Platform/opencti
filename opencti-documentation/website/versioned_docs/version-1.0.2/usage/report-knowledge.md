---
id: version-1.0.2-report-knowledge
title: Add knowledge to a report
sidebar_label: Add knowledge to a report
original_id: report-knowledge
---

## Introduction

On the OpenCTI platform, knowledge can only be added in the context of a report. **This ensure that all entities and its relationships to be sourced by at least one report**. Adding knowledge to a report can be done programmatically using OpenCTI connectors or through the [Python client](https://github.com/OpenCTI-Platform/client-python). This documentation is a guide for creating knowledge manually, if you wish to use the [Python client](https://github.com/OpenCTI-Platform/client-python), please referer to the [dedicated documentation](python/introduction).

To start adding knowledge to report you should:

1. Go the reports section and select the report you want to analyze.
2. At first you arrive in the overview section of the report. If your report has not been processed by anyone before, this section should be almost empty. The external reference box on the report dashboard allows you to access the PDF file of the report through the URL.

![Report overview](assets/usage/report_overview.png "Report overview")

3. Go to the knowledge tab at the top middle left of the window.

![Report knowledge](assets/usage/report_knowledge.png "Report knowledge")

## Knowledge management

In this space, you can start selecting entities in order to link them, on the basis of what is written in the report (*in this example, knowledge created does not reflect the content of the report*). First, click on the orange bottom right button. A window will unroll on the right side. You can use the "search" bar to find the information relevant to the report (TTPs, malwares, countries, sectors etc.).

![Report add knowledge](assets/usage/report_knowledge_add.png "Report add knowledge")

> *Note*: all the TTPs displayed in the demonstration or in this documentation are from the [MITRE ATT&CK framework](https://attack.mitre.org). But you can add any framework you want or build your own by adding TTPs on the platform.

* Each time you click on one element you wish to add, it will stack itself at the upper left of the workspace, just under the title. You can stack all the elements you need for now and unstack them as you organize them on the page and link them to each other.

* If one element you wish to add from the report is not in the OpenCTI database, you can create it by clicking again on the orange button at the bottom right of your window. Whatch out for duplicates!

> To avoid duplicates, especially with entities such as sectors, cities, countries and regions, we suggest you use the datasets on the [repository](https://github.com/OpenCTI-Platform/datasets) or create your own.*

* Once all the elements of interest are stacked, you can collapse the right window by clicking on the workspace and start unstacking and organizing the boxes on the space by clicking on them and dragging and dropping them.

* You then can start to create links between your different entities and techniques. 

> **The direction in which you draw the link matters a lot, so we strongly advise you to carefully read the [guide on creating relations](../reference/relations) before starting creating real cases.** As an exemple, if you draw a link from an intrusion set to a TTP, it will be a link of *APT-X uses TTP xx*, but you want to avoid drawing a link from the TTP to the APT as it does not make sense for an intrusion set to be used by a TTP. 

In some cases, a relation already exists between two entities. For instance, the relation between the tool "Cobalt Strike" using the TTP "credential dumping" will be created multiple times.

> We advise you create a new relation everytime it is mentionned, with the date matching the information in the report, instead of using always the same relation.

![Report existing relation](assets/usage/report_existing_relation.png "Report existing relation")

## Results

Once you have added all the entities and the relationships between them, the report knowledge is now complete:

![Report knowledge complete](assets/usage/report_knowledge_complete.png "Report knowledge complete")

All these new entities will be added to the "entities" section belonging to the report and will also appears in the stats in the "overview" section.

![Report entities](assets/usage/report_entities_complete.png "Report entities")

Obviously, you can update or suppress relations and suppress TTPs and entities if needed from anywhere in the platform. After you created knowledge of a report, the overview of the report will be updated.

![Report overview complete](assets/usage/report_overview_complete.png "Report overview complete")
# Artificial intelligence in OpenCTI

We are heavily working on multiple AI-powered features within the platform to help analysts save time and access actionable insights more easily. This page references all existing features and their associated documentation. All AI capabilities developed by Filigran are regrouped under the friendly name of "Ariane AI".

## Triaging and structuring

### Extract structured knowledge from raw data ✨

!!! success "Generally available"

    This feature is generally available for both SaaS and on-premise deployments.

The [connector ImportDocumentAI](https://github.com/OpenCTI-Platform/connectors/tree/master/internal-import-file/import-document-ai) is leveraging customized AI mechanisms to allow the platform parse raw files (PDFs, etc.) and transform them into structured data (STIX bundles) to be ingested by the platform.

!!! info "Outcomes"

    AI structured data extraction greatly enhance the ability to quickly import raw data / reports within the platform with the associated meaningful knowledge, making it directly actionable for analyst and third-parties.

### What's next in this category?

We are working on:

| Feature                             | Description                                                                         | 
|:------------------------------------|:------------------------------------------------------------------------------------|
| `Threats similarity engine`         | Help attribution and highlight critical changes in threats behaviors and knowledge. |
| `Top threats / reports highlights`  | Help highlights top threats / reports based on their content and the defined PIRs.  |

## Accessing and understanding

### Insights and summaries generation ✨

!!! success "Generally available"

    This feature is generally available for both SaaS and on-premise deployments.

The platform can easily [generate insights and summaries](../usage/insights.md) about a given entity based on the last pieces of knowledge associated to it (last reports, relationships, number of indicators etc.).

!!! info "Outcomes"

    Insights capabilities help analysts to understand trends and forecast about a threat or a victim (sector, geography, etc.) but also quickly access to summarized information of latest reports or cases.

### Platform assistant (interaction) ✨

!!! warning "Partially available"

    A first iteration of this feature has been released but more iterations needed.

It is currently possible to ask questions to the platform in natural language and get some results. The full scope would be to have a capacity to interact with the platform in natural language (*chatbot*), to refine questions and be able to create new reports, dashboards, etc.

!!! info "Outcomes"

    Platform assistant allows analysts to interact with the platform, ask questions, get relevant knowledge and take actions.

### What's next in this category?

We are working on:

| Feature                     | Description                                                                        | 
|:----------------------------|:-----------------------------------------------------------------------------------|
| `AI-driven PIR definition`  | Help to create relevant PIRs based on natural language and documents.              |

## Improving and evaluating

### Refine textual information ✨

!!! success "Generally available"

    This feature is generally available for both SaaS and on-premise deployments.

The platform helps users with [textual refinement](../usage/refine-content.md) to fix spelling mistakes, change tone and refine text-based properties.

!!! info "Outcomes"

    Refine textual information help users to quikly fix mistakes or just change the tone of any content within the platform, from description to larger content.

### What's next in this category?

We are working on:

| Feature                    | Description                                                                           | 
|:---------------------------|:--------------------------------------------------------------------------------------|
| `Evaluating data sources`  | Help understanding the relevance of data sources, scoring and overlaps between feeds. |

## Creating and generating

### Export of knowledge ✨

!!! success "Generally available"

    This feature is generally available for both SaaS and on-premise deployments.

The platform can help [generating reports about a given entity](../usage/export.md). It can be used to generate a full report or to generate one part of a report based on a template in the finished intelligence feature.

!!! info "Outcomes"

    AI can help generating full-fledged reports from threats or incident response, allowing analysts to quickly generating reports or to leverage AI to quickly fill some blank parts of finished intelligence templates.

### What's next in this category?

We are working on:

| Feature                   | Description                                                  | 
|:--------------------------|:-------------------------------------------------------------|
| `Generating dashboards`   | Ability to generate dashboards leveraging AI capabilities.   |
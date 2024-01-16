# Export in documents

!!! tip "Under construction"

    We are doing our best to complete this page. 
    If you want to participate, don't hesitate to join the [Filigran Community on Slack](https://community.filigran.io) 
    or submit your pull request on the [Github doc repository](https://github.com/OpenCTI-Platform/docs).
# Export

## Introduction

With the OpenCTI platform, you can manually export your intelligence content in two formats:

- structured with exports in .json and/or .csv formats,
- documents with exports in .pdf (.txt?) format

![Generate an export panel](assets/Generate_an_export_panel.png)

## Export in structured format

### Generate an export

To export one or more entities and direct or linked content you have two possibilities. First you can click on the button 'open export panel'. The list of pre-existing exports will open, and in the bottom right-hand corner you can configure and generate a new export.

![open export panel](assets/open_export_panel.png)

This opens the export settings panel, where you can customize your export according to three fields:

- desired export format (text/csv, application/pdf, application/vnd.oasis.stix+json, text/plain)
- export type (simple or full),
- the max marking definition level of the elements in the entity to be exported (a TLP level, for instance).

![customize your export](assets/customize_your_export.png)

The second way is to click direcly on the 'Generate an Export' button to export the content of an entity in the desired format. The same settings panel will open.

![Export entity content](assets/Export_entity_content.png)

### Export possibilities

All entities in your instance can be exported either directly via Generate Export or indirectly via Export List in .json and .csv formats.

### Export from one or more entities

You can choose to export a single element, such as a report and its contents, or a set of elements, such as several reports. These exports will contain not only the entity itself, but also related or unrelated elements, depending on the type of export you choose: 'simple' or 'full'.

### Export specific content within an entity

You can also choose to export only certain entities linked to your export object. To do so, go to the entity's internal panels.

For example, for a report, if you only want to retrieve entity_type Attack Pattern and indicators to design a detection strategy, go to the entities panel and select specific elements for export.

![Export specific elements](assets/Export_specific_elements.png)

### Export types (simple and full)

When you wish to export only the content of a specific entity such as a report, you can choose a 'simple' export type.

If you also wish to export associated content, you can choose a 'full' export. With this type of export, the entity will be exported along with all entities directly associated with the central one (first neighbors).

![Export types](assets/Export_types.png)

### Exports list

Once an export has been created, you can find it in the export list. Simply click on a particular export to download it. 

You can also generate a new export directly from the Exports list, as explained in the section “**How do I create an export?”**.

![Exports list](assets/Exports_list.png)
# Platform

## Introduction

The following chapter aims at giving the reader a step-by-step description of what is available on the platform and the meaning of the different tabs and entries.

When the user connects to the platform, the home page is the `Dashboard`. This `Dashboard` contains several visuals summarizing the types and quantity of data recently imported into the platform. It is described below.

The left side panel allows the user to navigate through different windows and access different views and categories of knowledge. These windows are detailed in the different pages linked below.

<aside>
👉 If you are looking for the full list of possible entities or relations, please refer to the page [Data model](https://www.notion.so/Data-model-a84f286a4e1641728ee3951120d45448).

</aside>

## General information on browsing

### Description of the welcome `Dashboard`

The welcome `Dashboard` gives any visitor on the OpenCTI platform an outlook on the live of the platform. The widgets which are displayed cannot be changed, suppressed, resized or moved around. They cannot be clicked except for one (ingested analysis). They are the following:

- Total entities: indicates the number of all entities present in the platform, with an indication the added entities in the last 24 hours.
- Total relationships: indicates the number of all relationships created in the platform, with an indication of added relationships in the last 24 hours.
- Total reports: indicates the number of total reports in the platform and the number of newly ingested reports in the last 24 hours.
- Total observables: indicates the number of total observables in the platform and the number of newly ingested observables in the last 24 hours.

The numbers indicating the variation only give how many new objects were added to the platform manually or using connectors. It compares the number of objects at D-1 and at D and establishes the variation number, therefore the variation will never be bellow 0.

- Top labels: indicates which are the top labels given to entities during the last 3 months. The top 9 labels are shown, with the number of entities having that label.
- Ingested entities: indicates how many entities were ingested and when over the last year.
- Top ten active entities (last 3 months): name and list of the entities with the greatest number of relations created to it in the platform over the last 3 months. The type of the entity and the exact number of relations is displayed if the mouse is moved over one bar. The entities can be any entity.
- Targeted countries: the map can be zoomed in and out, and display targeted countries in the world over the last 3 months. The intensity of the targeting, meaning the number of relations "targets" towards these countries, is reflect by 3 colors. Orange is for heavy targeting, pale orange of medium and yellow for low.
- Last ingested analysis: display the list of the last 8 objects belonging o the analysis section which have been created (manually or by a connector) in the platform. This included reports but also notes, opinions and external references. These can be clicked to access directly the page of the analysis.
- Observable distribution: indicates the 10 top observable types in the platform and the absolute number of entities for each type. As for the top 10 active entities, the value is displayed when the mouse is run over.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/498d1692-cdbc-4bb7-972d-aad16fde0650/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/498d1692-cdbc-4bb7-972d-aad16fde0650/Untitled.png)

### Presentation of a typical page in OpenCTI

Although there are many different entities in OpenCTI and many different tabs, most of them are quite similar and only have minor differences from the other, mostly due to some of their characteristics, which requires specific fields or do not require some fields which are necessary for the other. 

In this part will only be detailed a general outline of a "typical" OpenCTI page. The specifies of the different entities will be detailed in the corresponding pages below (Activities and Knowledge).

Entities are usually presented as such:

- an `Overview` tab, general page on the entity. Just as the welcome dashboard gives an overview of the whole platform, the `Overview` page of the entity gives an idea of the activity regading this entity. You can find general information on the entity such as the ID of the entity, the confidence level, the markings, the author and the creator, dates, description etc. as well as widgets that show the general activity on the entity, such as last relations created, latest reports mentionning the entity, most recent history and external references.

*Below are two images showing an "overview" tab of an intrusion set.*

![`Overview` tab of an intrusion set (top part)](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e909bb9e-3ec9-4f66-9bc5-8f4d825ef23b/overview_page_entity.png)

`Overview` tab of an intrusion set (top part)

![`Overview` tab of an intrusion set (bottom part)](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/10566dd7-39e3-4a8d-917c-8f43895802af/entity_overview_page_bottom.png)

`Overview` tab of an intrusion set (bottom part)

- A `Knowledge` tab, which is the central part of the entity. The `Knowledge` tab is different for a `Report` entity than for all the other tabs.
    - `Knowledge` tabs of any entity except for reports gather all the entities which have been at some point linked to the entity the user is looking at (for instance, as shown in the following capture, the `Knowledge` tab of Intrusion set APT29) gives access to the list of all entities APT29 is attributed to, all victims the intrusion set has targeted, all its campaigns, TTPs, malwares etc. . For entities to appear in theses tabs under `Knowledge`, they need to have been linked to the entity directly or have to be computed with the inference engine (to come).
    
    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/fef16ff6-1476-4cdb-b8e8-5aab782498c9/knowledgetab_intrusionset.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/fef16ff6-1476-4cdb-b8e8-5aab782498c9/knowledgetab_intrusionset.png)
    
    - The `Knowledge` tab of reports is the place to integrate and link together entities. For more information on how to integrate information in OpenCTI using the knowledge tab of a report, please refer to the part [Update the knowledge](https://www.notion.so/Update-the-knowledge-ecc7177d1fd74875ae9595c1f9a94571)

- The `Analysis` tab contains the list of all the reports in which the entity has been identified. The list can be ordered only by dates.

*Example of the list of reports in which the attack pattern "data obfuscation" has been identified.*

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9cafbffe-db42-47f8-9bcf-a97d3978ea1e/entity_analysis-tab.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9cafbffe-db42-47f8-9bcf-a97d3978ea1e/entity_analysis-tab.png)

- The `Files` tab

The file tab contains documents that are associated to the object and were either :

- Uploaded to the platform : for instance the PDF document containing the text of the report
- Generated from the platform to be downloaded : a JSON or CSV file containing information on the object and generatedby the user.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/ef3c4ce6-994c-4492-b87c-fe04c028a7b7/apt29_files.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/ef3c4ce6-994c-4492-b87c-fe04c028a7b7/apt29_files.png)

- The `History` tab

This tab display the history of change of the element, update of attributes, creation of relations, ...

Because of the volumes of information the history is written in a specific index by the history connector ([https://www.notion.so/luatix/History-17503579a70c467ba02ec11350c593bf](https://www.notion.so/History-17503579a70c467ba02ec11350c593bf)) that consume the redis stream to rebuild the history for the UI.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/17db48b7-3d3c-4d90-a52b-46c763635ce4/history.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/17db48b7-3d3c-4d90-a52b-46c763635ce4/history.png)

Less frequent tabs are the following:

- The `Indicators` tab (for all the threats and the entities in arsenal - except the courses of action -)
- The `Observables` tab (for reports, observed data
- the `Entities` tab (for reports and observed data)
- the `Sightings` tab (for Indicators and observables)
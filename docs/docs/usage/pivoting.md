# Pivot and investigate

In Opencti, all data can be represented as a large knowledge graph: everything is linked to something. 
You can pivot on any entity and on any relationship you have in your platform, using investigations.

Investigations are available on the top right of the top bar:

![Top menu investigation](assets/top-menu-investigation.png)

Investigations are organized by workspace. When you create a new empty workspace, it will only be visible by you and enables you to work on your investigation before sharing it.

In your workspace, you can add entities that you want to investigate, visualize the data linked to these entities, add relationships, and export your investigation graph in pdf, image or as new stix report.

![Investigation workspace](assets/investigation-workspace.png)

## Add and expand an entity

You can add any existing entity of the platform to your investigation.

![Investigation bottom right menu](assets/investigation-bottom-right-menu.png)

Once added, you can select the entity, and see its details in the right. 
In this bottom right menu, right next to "Add en entity", you can expand the selected entity and select the number of linked entities you want to see in your investigation.

![Investigation expand entity](assets/investigation-expand-entity.png)

## Add a relationship

You can add a relationship between entities directly in your investigation.

![Investigation create relationship](assets/investigation-create-relationship.png)

## Export your investigation

You can export your investigation in PDF or image format. 
You can also download all the content of your investigation graph in a **Report** stix bundle (investigation is automatically converted).

![Investigation export](assets/investigation-export.png)

## Turn your investigation to Report or Case

You can turn your investigation to :
- a grouping
- an incident response
- a report
- a request for information
- a request for takedown

![investigation-turn-to-report-or-case.png](assets/investigation-turn-to-report-or-case.png)

Either, you create a new report or case
![investigation-turn-to-report-or-case-dialog-new-entity.png](assets/investigation-turn-to-report-or-case-dialog-new-entity.png)

![investigation-turn-to-report-or-case-dialog-new-entity-form.png](assets/investigation-turn-to-report-or-case-dialog-new-entity-form.png)

Or, you select an existing entity
![investigation-turn-to-report-or-case-dialog-entity-selection.png](assets/investigation-turn-to-report-or-case-dialog-entity-selection.png)

![investigation-turn-to-report-or-case-dialog-entity-selection-add.png](assets/investigation-turn-to-report-or-case-dialog-entity-selection-add.png)

Once you have clicked on the `ADD` button, the browser will be redirected to the `Knowledge` tab of your new entity.
![investigation-turn-to-report-or-case-success.png](assets/investigation-turn-to-report-or-case-success.png)
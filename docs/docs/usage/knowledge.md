# Create knowledge

## Creating an entity from any page

The knowledge on the OpenCTI platform can be added by manually creating new entities or relationships.

In each list of entities, you can add new entities of the corresponding type by clicking on the "+" button on the bottom right of the page. For instance, if you are in the reports section, you will only be able to create reports. 

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/83a4a944-d292-4499-88c1-cfc880ae8be2/creation_modif.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/83a4a944-d292-4499-88c1-cfc880ae8be2/creation_modif.png)

A menu will appear and need to be filled out with information on the new entity, as shown in the image below. Only the name and the description are mandatory fields.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/6085dfab-72a8-4a8d-91f5-120455d8d5a2/menu_creation.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/6085dfab-72a8-4a8d-91f5-120455d8d5a2/menu_creation.png)

Labels and authors can be chosen from the scrolling menu, or created directly from this window, using the small "+" button, as shown below. In this example, you can see the temporary window for creating a new "author" while creating a new "intrusion set".

New marking levels cannot be added from this menu directly. Adding and editig marking levels is available in the "Settings" menu. Admin level-rights are required to edit the list of marking levels.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/03382659-7d1d-40b8-9ab7-9bbb743a1a32/creation_creation_modif.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/03382659-7d1d-40b8-9ab7-9bbb743a1a32/creation_creation_modif.png)

The creation menu contains the bare minimum of fields necessary to create the entity. More fields are available for modification once the entity is created, in the "editing" mode (see below for more informaiton on editing)

<aside>
💡 If you are looking for the whole OpenCTI data model (entities, properties), please refer to the dedicated documentation, which you can find here : [https://www.notion.so/luatix/Data-model-4427344d93a74fe194d5a52ce4a41a8d](https://www.notion.so/Data-model-a84f286a4e1641728ee3951120d45448)

</aside>

## Creating an entity within the knowledge tab of a report

Reports are a specific entity in the platform, allowing to trace back the source of a relation between two entities. The knowledge tab of a report is specific to this entity and different from the knwoledge tab of all other entities. 

The use of this tab is documented in a dedicated page. Please refer to the [Adding entities and relations within a report](https://www.notion.so/Adding-entities-and-relations-within-a-report-3c5acf91b180466992644dab8c1c859c) section.

## Editing the knowledge

You can edit any entity at any time using the three vertical dots right of the name of the entity, or the "pen" button at the bottom left of the page.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/eb72c584-92ce-499f-9865-90ea29f5319b/edit.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/eb72c584-92ce-499f-9865-90ea29f5319b/edit.png)

The editing mode allows the user to modify any of  the fields characterizing an entity, by giving access to two menus: 

- the "overview" menu is the same than the one for the creating of the entity. It allows to modify most of the "basic information" on the entity, except fields such as STIX IDS and the date of creation.
- the "details" menu is only accessible from the editing mode and allows to edit details on the entity, such as its motivations for an intrusion set etc.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/55a5c01b-5667-441a-a05a-a67ada18dfe1/editing_menu.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/55a5c01b-5667-441a-a05a-a67ada18dfe1/editing_menu.png)

A few fields are specific and can only be edited by clicking on the small orange "+" next to tem, which is dedicated to this field. The fields are :

- aliases
- labels
- external references (URL)
- notes
- for some entities, the "originates from" in the "details" section can also be edited only using such a "+" button

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/eb75a7bb-afee-4d9c-984c-a6eb966576fb/plusbutton.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/eb75a7bb-afee-4d9c-984c-a6eb966576fb/plusbutton.png)

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9c062ccd-ab19-4143-b6e6-d3bf0586caa1/plusbutton2.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/9c062ccd-ab19-4143-b6e6-d3bf0586caa1/plusbutton2.png)

## Duplicate alert while creating a new entity

The platform warns you of potential duplicates when you create a new entity. The platform will give a warning if others entities with the same string already exists. 

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/08fe1d6f-66e7-4a6b-92bb-373c89c7e67b/duplicates1b.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/08fe1d6f-66e7-4a6b-92bb-373c89c7e67b/duplicates1b.png)

The alert about duplicates is cliquable. Doing so will open a temporary scrolling menu, displaying all entities already containing this string. Entities can be of different types than the one currently being created. For instance, on the image below, malware containing the "APT1" string are also shown.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/bebce126-4fbd-4e97-a349-aadbfa6601db/duplicates2.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/bebce126-4fbd-4e97-a349-aadbfa6601db/duplicates2.png)

It is not possible to directly click on the entity of your choice if it already exists. You will need to abandon the creation you are currently doing by closing the window without validating the creation and afterwards search for the desired entity.

You can chose to ignore the alert by closing simply closing the temporary menu and continue adding information in the creation menu. 

<aside>
💡 ⚠️ If the new entity has exactly the same name and the same type as one already existing in the platform, will will be automatically merged at creation.

</aside>

For any other case (same name but different type, or different name, but the result appeared in the alert because the string exists in the other entity), no merge will be done, and your new entity will exists along the others.

To have more information on managing duplicates from the dedicated menu, refer to the page [Managing duplicates](https://www.notion.so/Managing-duplicates-46202c8e0abb43ff93bddacea4c40cb7)
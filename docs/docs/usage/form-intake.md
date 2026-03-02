# Create knowledge via Form Intake


It allows administrators to design structured forms that analysts fill out to quickly create STIX entities, relationships, and observables — without navigating complex creation dialogs.

## Key capabilities

- Visual form designer with field configuration and reordering 16 supported field types (text, date, select, toggle, lookup, vocabulary, etc.)
- Field width control (full, half, third)
- 4 entity creation modes: Single, Multiple, Parsed, and Lookup
- Additional entities and relationships in a single form
- STIX bundle generation from submissions
- Export/import form definitions across instances (JSON)
- Draft workspace integration

## Prerequisites & Permissions
More details on our [Role-Based access control here](../administration/users.md)

|Action |Details |Required Capability| Override of capabilities in draft (EE) |
|:------|:-------|:---------------------|---------------|
|Manage form intakes|Create, edit, delete, activate/deactivate, export, import|Manage ingestion|Capability not existing|
|Submit form intakes|Fill and submit forms|Create / Update knowledge| Create / Update knowledge (creation forced to draft)|
|View form intakes list| |Manage ingestion or Create / Update knowledge|Create / Update knowledge (creation forced to draft)|


When draft creation is enforced, form submissions create entities in a draft workspace for review before publication.
Administrators can optionally allow users to override draft mode per submission.
The form intake button is hidden when the user lacks Authorized Members update rights in draft context. See Enterprise Edition for details on capability overrides in draft.


## Defining a Form Intake
To create a form intake, go in the Ingestion menu, Form intake menu and click on Create.

Multiple fields are offered to you: 
- Name of your form intake
- Description of the form intake 
- Active (toggle on/off, default to on): when activated, your form will be present in the list.

## Main entity definition
Defining a main entity has two goals: 
- Be able to define in which screen, in addition to the import menu, you will see your form intake (ex: if your main entity is a Report, on the Report List view, you will see your form intake)
- Be able to specify which entity you want to create first (especially useful if it's a container.)

By default, main entity selected is a **Report**.

### Common fields

For each main entity, you can configure multiple fields: 
- **Entity Lookup** (disabled by default): if enabled, users will not be able to create any new entity, but will be forced to choose among existing entities. Another field will appear if you enable this field: **Disable on-the-fly entity creation**
- **Disable on-the-fly entity creation** (disabled by default): if you want your users to select some entities among existing ones, you may face an issue, if the entity they want to create does not exist. Enable this option to prevent from being able to create entity on the fly, to ensure strict entity lookup. 
- **Allow multiple instances of main entity** (disabled by default): if you want to allow your users multiple times the same entity.  If you enable this field, another field will appear **Multiple Mode**. 

#### Create multiple instances 
Create multiple instances of the same entity type is possible by enabling the above options. 
Several options exist to allow users to create several instances: 
   - By default, **multiple fields**: this option will allow users to create a new instance of the same type by simply clicking on a button
   - Parsed values: allow your users enter some text to be parsed based on a specific delimiter of your choice.

If you select the parsed value mode, additionnal options are offered to you: 
- Parse field type: Text or Text Area. 
- Parse mode: choose the delimiter between each value (default being comma-separated)
- Map parsed values to attribute: choose which value should the parsed text be mapped with.

**Warning**: when choosing to create multiple instance via parsed values, all the additional fields that you will define for the same entity type will be applied to all instances you will create. (Example: if you create multiple reports via parsed values, parsing on the name attribute, in you form intake, if you have added a description for reports, all created reports will have the same description).

### Supported entity Types as main entity
Any entity can be created as a main entity, whether it is a Stix Domain Object or a Stix Cyber Observable. 

By default, when selecting an entity type, the mandatory fields needed for [deduplication](deduplication.md) are automatically added. 

#### Main entity being a container

If your main entity is a container, any additional entities created will be contained in your container.
If several containers are created as once (via multiple mode enabled), all additional entities created will also be part of each containers. 

#### Main entity being an IOC or an Observable
If you want to allow your users to bulk create multiple IOCs or observable at once, you can setup a form intake that allows multiple entities to be created as once.

A specific option will be provided at this point: 
- **Automatically create indicators/observables from observables/indicators**: this will allow you to directly promote the created entities.


**Warning**: Given all containers are not created at once but one by one, you may also end up with the first container containing only the additionnal entities. And the other containers also containing other containers.


### Select fields for each entity type 

Selecting an entity type to create will allow you to select an attribute of this entity to populate.

Options for each field: 
- Map to attribute: choose the attribute of the entity that you need your users to provide (for instance, description).
- Field label: name your field with a custom label so that if your users are not acquainted with stix 2.1 they will be able to understand what is expected for them.
- Required: make it required. If the entity is not the main entity (and is not mandatory either), then you can proceed without filling the field
- Field width: size of the field on the screen (Full/half/third)

We support the following field types: 

|Field | Type |	Description|
|:-----|:-----|:-----------|
|Text |	Single-line |text input|
|Textarea	|Multi-line text input|
|Number	|Numeric input|
|DateTime|	Date and time picker|
|Checkbox	|Boolean checkbox|
|Toggle	|Boolean| on/off switch (respects defaultValue — e.g., Malware is_family)|
|Select	|Single-value| dropdown with predefined options|
|Multi-select|	Multi-value dropdown|
|Open Vocabulary|	|Vocabulary-based field with predefined values from OpenCTI vocabularies (auto-detected based on entity type and attribute)
|Created By|	|Set the author/creator identity
|Object Marking	||Apply marking definitions (TLP, PAP)
|Object Label	||Apply labels to created entities
|External References|	|Add external references
|Files	| |Attach files

**Warning:** If you have defined additional mandatory fields for an entity (ex: description) and your description is not added, you might end up with your entity not being created. 

## Additionnal entities definition

Once you have defined your main entity, you can define additional entities. 
It will allow your users to add additional entities within the same submission.


The same types and same modes are allowed to add additional entities. 

### Specificities of additional entity definition: required / not required and label

In addition to the various modes allowed to add additionnal entities, you have two other options: 
- If you enable the option **"allow multiple instances"**, then you will have the option to specify that this entity is optional by entering 0 in the minimum amount field. This means that you require at least 0 entity to be created, meaning that it is optional.
- If you disable the option **"allow multiple instances"**, then another option is offered to you: **required**. This will force the entity to be provided to submit the form.

Last but not least, you can also apply a **label to the entity to create**: this will allow users not experts with stix 2.1 to use the form to fill in entities without having to know that behind the scene, what you have defined as "attacker" will be created as an intrusion set for instance.

## Relationships 

You can define relationships to be created among entities

When you add a relation, you need to choose: 
- the Source entity (identified in the form by its label)
- the Target entity (identified in the form by its label)
- the relationship type (enabled as soon as Source & Target are provided)


The **relationship type** will only present compatible entities.

**Warning**: adding some relations in the form definition will not allow users to create the relation manually in the form. You need to toggle the **required** field to create the relation automatically at form submission. This means that any entities matching as source & targets will have relation created between them.


## Finalizing the submission: draft or not

You have the option, within the main entity, to enable an option **Create as draft by default**. If this option is enabled, another will be offered to your users: **Allow users to uncheck draft mode**.

This has been built to offer the advanced users the option to directly submit their input to the main database instead of a draft.

However, if your user is only able to create data via draft, due to the [capability specific to draft (entreprise edition)](../administration/users.md) whatever you selected, the user will not able to untick the box.

.

## Places to submit a form intake: 

Forms can be submitted from three locations:

- Entity list pages — Click the form intake toggle button (available on: Reports, Groupings, Malware, Case Incidents, Case RFIs, Case RFTs, Incidents, Campaigns, Intrusion Sets, Threat Actors Group, Threat Actors Individual, Indicators).
- Import dialog — Select "Import using a Form" in the import file dialog (displays full-width).
- Ingestion/form intake: when you click directly on the form intake you created, the form is prompted to you.

Note: The form intake button is hidden if the user lacks Create/update capability.

## Submission process
When a form is submitted, the following 7-step pipeline executes:

Step	Action	Details
1	Validate required fields	
2	Validate observable syntax	Backend checks format for observable entities (IPv4, IPv6, Domain, URL, Email, hashes). Invalid values throw INCORRECT_OBSERVABLE_FORMAT error.
3	De-sanitize/defang observables	Converts defanged IOCs: hxxp:// → http://, test[.]com → test.com
4	Map identity classes	Ensures correct STIX identity_class for Identity types: Individual → individual, Sector → class, System → system
5	Generate STIX bundle	
6	Auto-create indicators/observables	
7	Import bundle	Imports into OpenCTI directly, or into a draft workspace if draft mode is enabled

## Export
Export a form definition as a JSON file via the kebab menu → Export.
Includes the full schema, field configuration, entity types, and relationships.
Use for backup or cross-instance sharing.
Does not export previously submitted data.

## Import
Import a form definition from a JSON file via the Form Intakes list page.
The import dialog displays full-width for readability.
Cross-instance compatible — share form templates between OpenCTI instances (version ≥ 6.8.1).
Note: Verify version compatibility when importing across different OpenCTI versions.

## Delete
Delete via the kebab menu → Delete. Deletion is permanent and cannot be undone.
Previously submitted data (entities, relationships already created) is not affected — only the form definition is removed.


## GraphQL API Reference

Queries
graphql
Copy
### Get a single form by ID
`query GetForm($id: String!) {
  form(id: $id) {
    id
    name
    description
    entity_type
    schema
    created_at
    updated_at
  }
}`

### List all forms with filtering and search
`query ListForms($first: Int, $search: String, $orderBy: FormOrdering, $orderMode: OrderingMode) {
  forms(first: $first, search: $search, orderBy: $orderBy, orderMode: $orderMode) {
    edges {
      node {
        id
        name
        description
        entity_type
      }
    }
  }
}` 

### Create a new form
`mutation CreateForm($input: FormAddInput!) {
  formAdd(input: $input) {
    id
    name
  }
}`


### Delete a form
`mutation DeleteForm($id: ID!) {
  formDelete(id: $id)
}`

### Submit a filled form
`mutation SubmitForm($id: ID!, $input: FormSubmitInput!) {
  formSubmit(id: $id, input: $input) {
    id
  }
}`

## Best Practices

### Form Design
- Start simple: Begin with essential fields and iterate based on analyst feedback.
- Use Parsed mode for bulk IOCs: Comma or line-separated input is the fastest approach for high-volume observable ingestion.
- Set field widths strategically: Use third for short fields (dates, scores, markings), full for text areas.
- Mark only truly essential fields as required: Reduce friction for analysts while maintaining data quality.

### Data Ingestion
- Enable auto-create indicators from observables for actionable intelligence and detection pipeline integration.
- Do not enable both auto-create directions simultaneously (indicator → observable AND observable → indicator) to avoid circular creation loops.
- Use draft mode for high-volume ingestion to allow review before publication (Enterprise Edition).

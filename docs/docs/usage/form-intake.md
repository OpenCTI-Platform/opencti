# Create knowledge with Form intake

Form intake lets administrators design structured forms that analysts can submit to create STIX entities, cyber observables, and relationships. It provides a guided alternative to individual creation dialogs and can send submissions either directly to the knowledge base or to a draft for review.

## Key features

- Build forms from entity attributes and reorder the displayed fields.
- Create one or several instances of the main entity.
- Select existing entities or allow users to create them from lookup fields.
- Parse comma-separated or line-separated values for bulk creation.
- Add optional or required additional entities and relationships.
- Set default, required, or read-only field values.
- Create Indicators from observables or observables from Indicators.
- Create submissions in a draft and preconfigure draft metadata and access.
- Duplicate forms and export or import their JSON configuration.

## Permissions

For more information about capabilities, see [Roles and capabilities](../administration/users.md).

| Action | Required capability |
| --- | --- |
| Create, update, duplicate, activate, deactivate, import, export, or delete a form | **Manage ingestion** |
| Submit directly to the knowledge base | **Create / Update knowledge** |
| Submit to a draft | A compatible knowledge capability in draft mode; users restricted to draft creation cannot disable draft mode |
| View available forms | **Create / Update knowledge**, **Import knowledge**, or an applicable draft capability |

When draft creation is enforced by the form or by the user's capabilities, the submission creates a draft for review before ingestion.

The **Authorized Members** setting is available only to users who can manage authorized members in the applicable draft context. See [Control of capabilities in Draft mode](../administration/users.md#control-of-capabilities-in-draft-mode).

## Create a form

1. Go to **Integrations > Available**.
2. Select the **Built-in ingestion** category.
3. Find **Form intake**, then select **Create**.
4. Enter a name and description.
5. Leave **Active** enabled to make the form available for submission.
6. Configure the main entity, additional entities, relationships, and draft behavior.
7. Select **Create**.

Created forms appear under **Integrations > Deployed**. Select a form there to open and submit it.

## Configure the main entity

The main entity determines:

- The primary entity created or selected by the form.
- The entity list pages from which users can open the form.
- Whether additional entities can be included in a container.

The default main entity type is **Report**. You can select any supported STIX Domain Object, STIX Cyber Observable, or STIX Meta Object. OpenCTI automatically adds attributes that are mandatory for the selected entity type.

### Choose an entity entry mode

Configure the main entity with one of the following approaches:

| Configuration | Result |
| --- | --- |
| Single instance | The user completes one set of entity fields. |
| **Allow multiple instances of main entity** with **Multiple fields** | The user can add and complete several field groups. |
| **Allow multiple instances of main entity** with **Parsed values** | The user enters comma-separated values or one value per line. |
| **Entity lookup (select existing entities)** | The user selects one or more existing entities instead of completing entity fields. |

When lookup is enabled, users can create an entity from the lookup if they have the required creation capability. Enable **Disable on-the-fly entity creation** to restrict the field to existing entities only. An entity created from a lookup is submitted with the form, so it is created in the same draft when draft mode is used.

### Configure parsed values

Parsed mode is available when multiple instances are enabled. Configure:

- **Parse Field Type**: use a single-line text field or text area.
- **Parse Mode**: separate values with commas or, for a text area, enter one value per line.
- **Map parsed values to attribute**: select the string attribute that receives each parsed value.
- **Automatically convert to STIX patterns**: for Indicators, convert submitted observable values to STIX patterns.

Additional fields in parsed mode apply to every entity created from the parsed values. For example, if values map to a Report name and the form also contains a description, every generated Report receives the same description.

### Include entities in a container

For a container main entity, enable **Include entities in container** to include additional entities in the container.

If the form creates several containers, each container contains the additional entities. Containers are processed sequentially, so later containers can also contain containers created earlier in the submission.

### Create Indicators and observables automatically

For Indicator and observable forms, you can enable:

- **Automatically create observables from indicators**
- **Automatically create indicators from observables**

Enable only the direction required by the form to avoid unnecessary circular creation.

## Configure entity fields

For every main or additional entity field, configure:

- **Map to attribute**: the entity attribute populated by the field.
- **Field Type**: a compatible input for the selected attribute.
- **Field Label**: the label shown to users.
- **Description**: guidance displayed with the field.
- **Required**: whether the user must provide a value.
- **Read only** and **Default value**: provide a value that users cannot change.
- **Field width**: full, half, or one-third of the form width.

Mandatory entity attributes cannot normally be removed. In parsed mode, the parsed attribute supplies the deduplication value, and the form can apply other configured fields to all generated entities.

Supported field types include:

| Field type | Usage |
| --- | --- |
| Text | Single-line string input |
| Text Area | Multi-line string, Markdown, or text input |
| Number | Numeric, integer, or floating-point input |
| Date & Time | Date and time input |
| Checkbox / Toggle | Boolean input |
| Select / Multi-Select | One or several predefined values |
| Open Vocabulary | Values from the OpenCTI vocabulary mapped to the attribute |
| Created By | Author identity |
| Object Marking | Marking definitions such as TLP or PAP |
| Object Label | Labels applied to created entities |
| External References | Existing external references |
| Files | File attachments, with optional multiple-file support |

!!! warning

    A required or mandatory attribute must have either a user-provided value or a configured default value. Otherwise, the form cannot create the entity.

## Configure additional entities

Use the **Additional Entities** tab to add other entities to the same submission. For each entity:

1. Select its entity type.
2. Set **Label for entities** to provide a user-friendly role, such as `Attacker`.
3. Choose single, multiple, parsed, or lookup behavior.
4. Configure its fields.

For a single entity, enable **Required** to require it. An optional additional entity is omitted when the user leaves all its fields empty. If any field is completed, its required attributes must also be provided.

For multiple entities, **Minimum amount** controls how many entries are required. Set it to `0` to make the entire entity group optional.

Lookup and parsed behavior works the same way as for the main entity, including on-the-fly creation and additional fields shared by parsed entities.

## Configure relationships

The **Relationships** tab becomes available after you add an additional entity.

For each relationship:

1. Select the source entity and target entity by their configured labels.
2. Select a compatible relationship type.
3. Enable **Required** to create the relationship automatically for matching source and target instances.
4. Optionally add fields for the relationship.

Relationship fields can populate description, confidence, status, start time, stop time, author, markings, and labels, depending on the selected field type.

Users do not manually add relationships while completing the form. Only relationships enabled as **Required** are created on submission.

## Configure draft creation

Enable **Create as draft by default** to send submissions to a draft. Enable **Allow users to uncheck draft mode** if users with sufficient capabilities may submit directly to the knowledge base.

Users whose capabilities restrict them to draft creation cannot disable draft mode, even when the form allows an override.

### Set draft defaults

Expand **Advanced Draft Settings** to configure:

| Draft field | Available configuration |
| --- | --- |
| Name | Default value, editable by user, required |
| Description | Default value, editable by user, required |
| Assignees | Default users, editable by user, required |
| Participants | Default users, editable by user, required |
| Author | No default, reuse the main entity author, or select a specific author; editable by user; required |
| Authorized Members | Activate access restriction, set defaults, and allow editing |

Form-level defaults and requirements take precedence over draft entity customization. This ensures that a form produces the draft structure selected by its administrator.

The draft author and authorized members remain subject to role-based access control (RBAC). A selected identity that the submitter cannot access can appear as restricted in the draft.

### Use dynamic authorized members

Authorized members can include dynamic values resolved when the draft is created:

- **Creators**: the user who submitted the form.
- **Draft author (org)**: the draft author's organization, optionally intersected with a group.
- **Assignees**: the draft assignees.
- **Participants**: the draft participants.

Assign the required access right to each member. A user who receives **Can manage** on the draft but lacks the **Manage authorized members** capability still cannot change its authorized members.

If a [draft workflow](draft-workflow.md) is published, the draft created by the form uses that workflow like any other draft.

## Submit a form

Users can open active forms from:

- **Integrations > Deployed**, by selecting the form.
- A supported entity list page that matches the form's main entity type.
- The file import dialog, by selecting **Import using a Form**.

The form action is hidden when the user lacks the capability required to submit it.

On submission, OpenCTI:

1. Validates required values and entity attributes.
2. Validates observable syntax and restores defanged values such as `hxxp://` and `[.]`.
3. Resolves existing entities and prepares entities created from lookup fields.
4. Maps identity classes and creates the configured STIX objects.
5. Creates configured relationships and container references.
6. Creates any requested Indicators or observables.
7. Sends the STIX bundle for ingestion, either directly or through the created draft.

## Manage form definitions

Open the action menu for a deployed Form intake to:

- **Update** its definition or activation state.
- **Duplicate** it as the starting point for another form.
- **Export** its complete JSON configuration.
- **Delete** the form definition.

Exported configurations contain the form schema and settings, but not previously submitted data. Import a JSON configuration from the **Form intake** card under **Integrations > Available**. Verify version compatibility before importing a form exported from another OpenCTI instance.

Deleting a form does not delete entities or relationships created by earlier submissions.

## GraphQL API reference

### Get a form

```graphql
query GetForm($id: ID!) {
  form(id: $id) {
    id
    name
    description
    active
    form_schema
    created_at
    updated_at
  }
}
```

### List forms

```graphql
query ListForms(
  $first: Int
  $search: String
  $orderBy: FormsOrdering
  $orderMode: OrderingMode
) {
  forms(
    first: $first
    search: $search
    orderBy: $orderBy
    orderMode: $orderMode
  ) {
    edges {
      node {
        id
        name
        description
        active
        form_schema
      }
    }
  }
}
```

### Create a form

The `form_schema` value is a JSON-encoded string.

```graphql
mutation CreateForm($input: FormAddInput!) {
  formAdd(input: $input) {
    id
    name
    active
  }
}
```

### Update a form

```graphql
mutation UpdateForm($id: ID!, $input: [EditInput!]!) {
  formFieldPatch(id: $id, input: $input) {
    id
    name
    active
    form_schema
  }
}
```

### Submit a form

The `values` property in `FormSubmissionInput` is a JSON-encoded string containing the completed form values.

```graphql
mutation SubmitForm(
  $input: FormSubmissionInput!
  $isDraft: Boolean!
) {
  formSubmit(input: $input, isDraft: $isDraft) {
    success
    bundleId
    message
    entityId
  }
}
```

### Import and export a form

```graphql
mutation ImportForm($file: Upload!) {
  formImport(file: $file) {
    id
    name
  }
}

query ExportForm($id: ID!) {
  form(id: $id) {
    toConfigurationExport
  }
}
```

## Best practices

- Start with the minimum fields required for deduplication and analysis.
- Use explicit labels and descriptions for users who do not work directly with STIX concepts.
- Use parsed mode for bulk observable or Indicator creation.
- Use lookup mode when the form should connect new information to existing knowledge.
- Use read-only defaults for values that must remain consistent across submissions.
- Use draft mode when submissions require review, access control, or workflow approval.

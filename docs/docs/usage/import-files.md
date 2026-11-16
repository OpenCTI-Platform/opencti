# Import from files


## Import mechanisms

The platform provides a seamless process for automatically parsing data from various file formats. This capability is facilitated by two distinct mechanisms.

**File import connectors:** Currently, there are four connectors designed for importing files and automatically identifying entities.

- `ImportFileStix`: Designed to handle STIX-structured files (json or xml format).
- `ImportFileMISP`: Designed to handle MISP-structured files (json format).
- `ImportFileYARA`: Designed to handle YARA rules files (yar format).
- `ImportDocument`: Versatile connector supporting an array of file formats, including pdf, text, html, and markdown.

**CSV mappers:** The CSV mapper is a tailored functionality to facilitate the import of data stored in CSV files. For more in-depth information on using CSV mappers, refer to the [CSV Mappers](../administration/csv-mappers.md) documentation page.

![Manual import connectors](assets/manual-import-connectors.png)


## Usage

### Locations

Both mechanisms can be employed wherever file uploads are possible. This includes the "Data" tabs of all entities and the dedicated panel named "Data import and analyst workbenches" located in the top right-hand corner (database logo with a small gear). Importing files from these two locations is not entirely equal; refer to the "Relationship handling from entity's Data tab" section below for details on this matter.

### Entity identification process

For `ImportDocument` connector, the identification process involves searching for existing entities in the platform and scanning the document for relevant information. In additions, the connector use regular expressions (regex) to detect IP addresses and domains within the document.

As for the `ImportFileStix` connector and the CSV mappers, there is no identification mechanism. The imported data will be, respectively, the data defined in the STIX bundle or according to the configuration of the CSV mapper used.

### Workflow overview

1. Upload file: Navigate to the desired location, such as the "Data" tabs of an entity or the "Data import and analyst workbenches" panel. Then, upload the file containing the relevant data by clicking on the small cloud with the arrow inside next to "Uploaded files".
2. Entity identification: For a CSV file, select the connector and CSV mapper to be used by clicking on the icon with an upward arrow in a circle. If it's not a CSV file, the connector will launch automatically. Then, the file import connectors or CSV mappers will identify entities within the uploaded document.
3. Review and validation: Entities identified by connectors are not immediately integrated into the platform's knowledge base. Instead, they are placed in a draft (or a workbench, depending on the selected validation mode), awaiting review and validation by an analyst. By default, a draft is created. For more information on drafts, refer to the [Draft workspaces](draftWorkspaces.md) documentation page, or for workbenches, the [Analyst workbench](workbench.md) page.

!!! warning "Review imported data"

    Import connectors may introduce errors in identifying object types or add "unknown" entities. Drafts and workbenches were established with the intent of reviewing the output of connectors before validation. Therefore, it is crucial to be vigilant when examining the draft or workbench to prevent the import of incorrect data into the platform.

![Global import panel](assets/global-import-panel.png)


## Additional information

### Validation mode for CSV mapper

CSV mappers are never triggered automatically on upload: you always launch them manually. Their output then follows the selected validation mode:

- **Draft** (the default): the data produced by the CSV mapper is placed in a [draft](draftWorkspaces.md), like the output of other import connectors.
- **Workbench**: when you import the file from the import dialog, the data is placed in a [workbench](workbench.md). When you use **Launch an import** on a file that is already uploaded, the data is imported directly into the platform, unless the `import_csv_built_in_connector:validate_before_import` parameter (environment variable `IMPORT_CSV_BUILT_IN_CONNECTOR__VALIDATE_BEFORE_IMPORT`, default `false`) is set to `true`, in which case a workbench is created. See [Use a mapper for importing a CSV file](../administration/csv-mappers.md#use-a-mapper-for-importing-a-csv-file).

### Relationship handling from entity's "Data" tab

When importing a document directly from an entity's "Data" tab, there can be an automatic addition of relationships between the objects identified by connectors and the entity in focus. The process differs depending on the type of entity in which the import occurs:

- If the entity is a container (e.g., Report, Grouping, and Cases), the identified objects in the imported file will be linked to the entity (upon draft or workbench validation). In the context of a container, the object is said to be "contained".
- For entities that are not containers, a distinct behavior unfolds. In this scenario, the identified objects are not linked to the entity, except for Observables. `Related to` relationships between the Observables and the entity are automatically added to the draft or workbench and created after validation.


### File import in Content tab

Expanding the scope of file imports, users can seamlessly add files in the `Content` tab of [Analyses](exploring-analysis.md) or [Cases](exploring-cases.md). In this scenario, the file is directly added as an attachment without utilizing an import mechanism.

### User capability requirement

In order to initiate file imports, users must possess the requisite [capabilities](../administration/users.md):

- "Upload knowledge files": upload files in the "Data" and "Content" sections of entities.
- "Import knowledge": trigger the ingestion of an uploaded file by an import connector or a CSV mapper.

These capabilities ensure that only authorized users can contribute and manage knowledge files within the OpenCTI platform, maintaining a controlled and secure environment for data uploads.

To import files into a draft only, a user can instead hold "Import knowledge" in the [capabilities in draft](../administration/users.md#control-of-capabilities-in-draft-mode) (Enterprise Edition). This capability is required to create a draft from a file upload.


!!! warning "Deprecation warning"

    Using the `ImportDocument` connector to parse CSV file is now disallowed as it produces inconsistent results.
    Please configure and use [CSV mappers](../administration/csv-mappers.md) dedicated to your specific CSV content for a reliable parsing.
    CSV mappers can be created and configured in the administration interface.   

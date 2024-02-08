# CSV Mappers

In OpenCTI, CSV Mappers allow to parse CSV files in a STIX 2.1 Objects. The mappers are created and configured by users with the Manage CSV mappers capability. Then, they are available to users who import CSV files, for instance inside a report or in the global import view.

## Principles

The mapper contains __representations__ of STIX 2.1 entities and relationships, in order for the parser to properly extract them. One mapper is dedicated to parsing a specific CSV file structure, and thus dedicated mappers should be created for every specific CSV structure you might need to ingest in the platform.

## Create a new CSV Mapper

In menu _Data_, select the submenu _Processing_, and on the right menu select _CSV Mappers_. You are presented with a list of all the mappers set in the platform. Note that you can delete or update any mapper from the context menu via the burger button beside each mapper.

Click on the button __+__ in the bottom-right corner to add a new Mapper.

Enter a name for your mapper and some basic information about your CSV files: 

- The line separator used (defaults to the standard comma character)
- The presence of a header on the first line

!!! info "header management"

    The parser will not extract any information from the CSV header if any ; it will just skip the first line during parsing.

![Creating a new CSV Mapper](assets/csv-mappers-create.png)

Then, you need to create every representation, one per entity and relationship type represented in the CSV file.
Click on the __+__ button to add an empty representation in the list, and click on the chevron to expand the section and configure the representation.

Depending on the entity type, the form contains the fields that are either required (input outlined in red) or optional.
For each field, set the corresponding columns mapping (the letter-based index of the column in the CSV table, as presented in common spreadsheet tools). 

References to other entities should be picked from the list of all the other representations already defined earlier in the mapper.

You can do the same for all the relationships between entities that might be defined in this particular CSV file structure.

![New representation](assets/csv-mappers-rep-1.png)

Fields might have options besides the mandatory column index, to help extract relevant data:

- __Date__ values are expected in [ISO 8601](https://en.wikipedia.org/wiki/ISO_8601?oldformat=true) format, but you can set your own format to the time parser
- __Multiple values__ can be extracted by specifying the separator used inside the cell (e.g. `+` or `|`)

Or to set default values in case some data is missing in the imported file.

![Field options](assets/csv-mappers-field-options-1.png)

## CSV Mapper validity

The only parameter required to save a CSV Mapper is a name ; creating and refining its representations can be done iteratively.

Nonetheless, all CSV Mappers go through a quick validation that checks if all the representations have all their mandatory fields set. 
Only valid mappers can be run by the users on their CSV files.

Mapper validity is visible in the list of CSV Mappers as shown below.

![An invalid CSV Mapper](assets/csv-mappers-invalid.png)

## Test your CSV mapper

In the creation or edition form, hit the button __Test__ to open a dialog. Select a sample CSV file and hit the __Test__ button.

The code block contains the raw result of the parsing attempt, in the form of a STIX 2.1 bundle in JSON format.

You can then check if the extracted values match the expected entities and relationships.

![Test a CSV Mapper](assets/csv-mappers-test.png)


## Use a mapper for importing a CSV file

You can change the default configuration of the import csv connector in your configuration file.
```json
"import_csv_built_in_connector": {
  "enabled": true, 
  "interval": 10000, 
  "validate_before_import": false
},
```

In Data import section, or Data tab of an entity, when you upload a CSV, you can select a mapper to apply to the file. 
The file will then be parsed following the representation rules set in the mapper.

By default, the imported elements will be added in a new Analyst Workbench where you will be able to check the result of the import.

## Default values for attributes

In the case of the CSV file misses some data, you can complete it with default values. To achieve this you have two possibilities:

- Set default values in the settings of the entities,
- Set specific default values directly in the CSV mapper.

### Set default values in the settings of the entities

!!! info "Default value mechanisms"

    Note that adding default values in settings have an impact at entity creation globally on the platform, not only on CSV mappers. If you want to apply those default values only at CSV mapper level, please use the second option.

In _settings_ __>__ _Customization_, you can select an entity type and then set default values for its attributes.

![mapper-settings](assets/csv-mapper-settings.png)

In the configuration of the entity, you have access to the entity's attributes that can be managed.

Click on the attribute to add a __default value__ information.

![mapper-custom](assets/csv-mapper-attribute.png)

Enter the __default value__ in the input and save the update.

![mapper-attribute](assets/csv-mapper-default.png)

The value filled will be used in the case where the CSV file lacks data for this attribute.

### Set specific default values directly in the CSV mapper

!!! info "Information retained in case of default value"

    If you fill a default value in entity settings and the CSV mapper, the one from CSV mapper will be used.

In the mapper form, you will see next to the column index input a gear icon to add extra information for the attribute. If the attribute can have a customizable default value, then you will be able to set one here.

![mapper-attribute](assets/csv-mappers-default-values.png)

The example above shows the case of the attribute `architecture implementation` of a malware. You have some information here. First, it seems we have a default value already set in entity settings for this attribute with the value `[powerpc, x86]`. However, we want to override this value with another one for our case: `[alpha]`.

### Specific case of marking definitions

For marking definitions, setting a default value is different from other attributes. We are not choosing a particular marking definition to use if none is specified in the CSV file. Instead, we will choose a default policy and we have two:

![mapper-attribute](assets/csv-mappers-default-markings.png)

- Use the default marking definitions of the user. In this case the default marking definitions of the connected user importing the CSV file will be used,
- Let the user choose marking definitions. Here the user importing the CSV file will choose marking definitions (among the ones they can see) when selecting the CSV mapper.

## Additional resources

- **Usefulness:** To additional content on entity customization, refers to the [Customize entities](./entities.md) page in the Administration section of the documentation.

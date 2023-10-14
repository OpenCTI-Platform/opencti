# Import from files

The `ImportDocument` connector allows to parse several types of files once you have uploaded them, for instance when attaching a file to a report.
The compatible file types are PDF, plain text, HTML, markdown or CSV.

Importing file can be done in the `Data` tab of each entity. Upload your file and select the importDocument connector or any more specific connector you may have available. Your file will be associated with the entity your are on. 

It is also possible to import files from the Data Import page, accessible from the top right menu. The file will not be associated with an entity. 

By default, the parsed content of the imported file will be added to a new Analyst Workbench to be reviewed.

Finally, you can also import files in the `Content` tab of [Analyses](exploring-analysis) or [Cases](exploring-cases.md). In this case, the file will be directly added as an attachment and won't use an import connector.

To be able to import a file, a user must have the [capability](../administration/users.md) "Upload knowledge files".

!!! warning Deprecation warning

    Using the `ImportDocument` connector to parse CSV file will be disallowed in the next version of OpenCTI as it produces inconsistent results.
    Please configure and use CSV mappers dedicated to your specific CSV content for a reliable parsing.
    CSV mappers can be created and configured in the [administration interface](../administration/csv-mappers.md).   
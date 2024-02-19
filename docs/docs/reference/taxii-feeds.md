# Taxii feeds
In OpenCTI, you can import TAXII collections from the Data tab, then Ingestion under the TAXII Feeds tab.

![TAXII Feeds panel.png](assets/TAXII_Feeds_panel.png)

## TAXII feeds management interface

On the first page, you'll find the TAXII Feeds already set up. For each one, you'll see the name, the url of the source TAXII server, the version, the running status and the current feed status.

Please note that OpenCTI only supports TAXII version 2.1.

## Create a TAXII ingester

![Create a TAXII ingester.png](assets/Create_a_TAXII_ingester.png)

To set your ingestion parameters, click on the Add button in the bottom right-hand corner.

Once the panel is open, you can enter:

- a name,
- a description for your feed,
- the URL address of your TAXII server,
- the version (2.1 is required for OpenCTI to ingest it),
- the name of the TAXII collection you wish to ingest,
- the type of authentication on your TAXII server so that OpenCTI can access your feed.
    - either basic access with a user / password pair,
    - or the bearer token,
    - or the client certificate,
- the earliest date desired for the import; note that if no date is entered, all items in the TAXII collection will be ingested.
- finally, enter a user responsible for data creation (if the field is left blank, the data will be created by the "System" user).

Once your TAXII feed is configured, simply click on the three vertical dots to the right of the ‘current state’ column and select 'start'. If this doesn't work, or if you wish to modify the settings, you can ‘update’ them by clicking on the same three vertical dots.

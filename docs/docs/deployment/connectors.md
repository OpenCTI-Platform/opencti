# Connectors

## Introduction

<aside>
💡 You are looking for the available connectors? The list is in the [OpenCTI Ecosystem](https://www.notion.so/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76).

</aside>

Connectors are the cornerstone of the OpenCTI platform and allow organizations to easily ingest, enrich or export new data on the platform. According to their functionality and use case, they are categorized in following classes:

External Import Connector

Automatically retrieve information from an external entity or service and import it into OpenCTI

Stream Input Connector

Connect to a data stream and continously ingest the retrieved information into OpenCTI. When used in combination with EDR systems like Tanium, the connector is also able to answer the originating system and turn this into a two way interaction between another system and OpenCTI.

Internal Enrichment Connector

SDOs and SCOs can be enriched using external lookup services to increase the knowledge of that object in OpenCTI. An example would be a *whois* lookup for an IP address.

Internal Import File Connector

Information from an uploaded file can be extracted and ingested into OpenCTI. Examples are files attached to a report or a json (STIX2) file.

Internal Export Connector

Information stored in OpenCTI can be extracted into different file formats like .csv or .json (STIX 2).

**Those connectors should be launched with a user that has an “Administrator” role (with bypass all capabilities enabled).**

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/385588d7-fcf7-4807-b536-b4d60e7656c7/Untitled.png)

API Interactions

API interactions are not connectors per definition, nonetheless they allow a script or a program to interact with OpenCTI using a client library.

## Information Processing

Every data the connector wants to sent to OpenCTI has to be converted into a STIX2 object, which will then be pushed via a messaging system to the OpenCTI worker. 

The worker is responsible for the error and performance handling and for interacting with the OpenCTI API interface for creating or updating the respective objects.

<aside>
💡 For the moment, only a valid STIX2 bundle is supported, by we intend to support CSV and other formats in the future.

</aside>

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/6de31dd5-17b8-4897-9295-aa3a6d597695/connector_architecture.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/6de31dd5-17b8-4897-9295-aa3a6d597695/connector_architecture.png)

## Connector configuration

All connectors have to be able to access to the OpenCTI API. To allow this connection, they have 2 mandatory configuration parameters, the `OPENCTI_URL` and the `OPENCTI_TOKEN`. In addition of these 2 parameters, connectors have other mandatory parameters that need to be set in order to get them work.

<aside>
⚠️ Be careful, we advise you to use a dedicated token for each of your connector. So you have to create a specific user for each of your connector. 

**All users for connectors should have the “Connector” role except “Workers” and “internal-import-files/internal-export-files Connectors” which should run with an Administrator user.**

You can see the user token by clicking on "Edit" on a user in the Settings / Accesses / Users panel. Please see the section *Create Connector User and Role* at the end of this page for detailed user and role creation.

</aside>

Example in a `docker-compose.yml` file:

Example in a `config.yml` file:

```docker
- CONNECTOR_ID=ChangeMe
- CONNECTOR_TYPE=EXTERNAL_IMPORT
- CONNECTOR_NAME=MITRE ATT&CK
- CONNECTOR_SCOPE=identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report
- CONNECTOR_CONFIDENCE_LEVEL=3
- CONNECTOR_UPDATE_EXISTING_DATA=true
- CONNECTOR_LOG_LEVEL=info
```

```yaml
-connector:
  id: 'ChangeMe'
  type: 'EXTERNAL_IMPORT'
  name: 'MITRE ATT&CK'
  scope: 'identity,attack-pattern,course-of-action,intrusion-set,malware,tool,report'
  confidence_level: 3
  update_existing_data: true
  log_level: 'info'
```

## Docker activation

You can either directly run the Docker image of connectors or add them to your current `docker-compose.yml` file.

### Add a connector to your deployment

For instance, to enable the MISP connector, you can add a new service to your `docker-compose.yml` file:

```docker
  connector-misp:
    image: opencti/connector-misp:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=MISP
      - CONNECTOR_SCOPE=misp
      - CONNECTOR_CONFIDENCE_LEVEL=3
      - CONNECTOR_UPDATE_EXISTING_DATA=false
      - CONNECTOR_LOG_LEVEL=info
      - MISP_URL=http://localhost # Required
      - MISP_KEY=ChangeMe # Required
      - MISP_SSL_VERIFY=False # Required
      - MISP_CREATE_REPORTS=True # Required, create report for MISP event
      - MISP_REPORT_CLASS=MISP event # Optional, report_class if creating report for event
      - MISP_IMPORT_FROM_DATE=2000-01-01 # Optional, import all event from this date
      - MISP_IMPORT_TAGS=opencti:import,type:osint # Optional, list of tags used for import events
      - MISP_INTERVAL=1 # Required, in minutes
    restart: always
```

### Launch a standalone connector

To launch standalone connector, you can use the `docker-compose.yml` file of the connector itself. Just download the latest [release](https://github.com/OpenCTI-Platform/connectors/releases) and start the connector:

```
$ wget https://github.com/OpenCTI-Platform/connectors/archive/{RELEASE_VERSION}.zip
$ unzip {RELEASE_VERSION}.zip
$ cd connectors-{RELEASE_VERSION}/misp/

```

Change the configuration in the `docker-compose.yml` according to the parameters of the platform and of the targeted service. Then launch the connector:

```
$ docker-compose up
```

<aside>
⚠️ Be careful that some connectors will try to connect to the RabbitMQ based on the RabbitMQ configuration provided for the OpenCTI platform. The connector must be able to reach RabbitMQ on the specified hostname and port. If you have a specific Docker network configuration, please be sure to adapt your `docker-compose.yml` file in such way that the connector container gets attached to the OpenCTI Network, e.g.:

```yaml
networks:
  default:
    external: true
    name: opencti-docker_default
```

More details on: [https://docs.docker.com/compose/networking/#use-a-pre-existing-network](https://docs.docker.com/compose/networking/#use-a-pre-existing-network)

</aside>

## Manual activation

If you want to manually launch connector, you just have to install Python 3 and pip3 for dependencies:

```
$ apt install python3 python3-pip
```

Download the [release](https://github.com/OpenCTI-Platform/connectors/archive/%7BRELEASE_VERSION%7D.zip) of the connectors:

```
$ wget <https://github.com/OpenCTI-Platform/connectors/archive/{RELEASE_VERSION}.zip>
$ unzip {RELEASE_VERSION}.zip
$ cd connectors-{RELEASE_VERSION}/misp/src/

```

Install dependencies and initialize the configuration:

```
$ pip3 install -r requirements.txt
$ cp config.yml.sample config.yml
```

Change the `config.yml` content according to the parameters of the platform and of the targeted service and launch the connector:

```
$ python3 misp.py
```

<aside>
⚠️ Be careful that some connectors will try to connect to the RabbitMQ based on the RabbitMQ configuration provided for the OpenCTI platform. The connector must be able to reach RabbitMQ on the specified hostname and port.

</aside>

## Connectors status

The connector status can be displayed in the dedicated section. You will be able to see the statistics of the RabbitMQ queue of the connector:

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a548ee12-8d44-45f9-a013-c95e412aec1b/connectors.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/a548ee12-8d44-45f9-a013-c95e412aec1b/connectors.png)

<aside>
➡️ If you encounter problems deploying OpenCTI or connectors, you can consult the [Troubleshooting](https://www.notion.so/Troubleshooting-4927527403c64d8aac2ac2e127ff464b) page. If not, go to the next section, the [Introduction](https://www.notion.so/Introduction-31c3e69442da4d84b8d6c60aa2a86833) page.

</aside>

## Create Connector User and Role

To have all the great history, access control and changelog features of OpenCTI you need to create a dedicated user per connector.

This guide assumes OpenCTI is running at [http://localhost:8080](http://localhost:8080) please change for your real URL.

**The “Internal Export File” connectors should be launched with a user that has an “Administrator” role (with bypass all capabilities enabled).**

### Create a connector role

Go to [http://localhost:8080/dashboard/settings/accesses/roles](http://localhost:8080/dashboard/settings/accesses/roles)

Click on the red + in the bottom right corner and fill out the role details and click "CREATE".

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8bd076a0-5af0-4f5b-9b57-1fd5372f53be/Screenshot_2021-03-25_at_14.27.59.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8bd076a0-5af0-4f5b-9b57-1fd5372f53be/Screenshot_2021-03-25_at_14.27.59.png)

After the Role has been created you can click on the three dots on the right side of the role table entry and click on "Update".

The following capabilities are necessary for all connectors to work correctly:

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/2665c2d9-e7c7-43db-97b1-22873f8cc856/Screenshot_2021-03-25_at_16.45.28.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/2665c2d9-e7c7-43db-97b1-22873f8cc856/Screenshot_2021-03-25_at_16.45.28.png)

### Create a connector user and attach role

Now you can create a user per connector.

Go to [http://localhost:8080/dashboard/settings/accesses/users](http://localhost:8080/dashboard/settings/accesses/users) and click the red + in the bottom right corner.

**The “Internal Export File” connectors should be launched with a user that has an “Administrator” role (with bypass all capabilities enabled).**

This example is creating a user for the Hygiene Connector. *Remember to use a long and complex password for every user:*

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f7a6c70a-0769-49ca-87a5-f1349578445b/Screenshot_2021-03-25_at_15.09.45.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f7a6c70a-0769-49ca-87a5-f1349578445b/Screenshot_2021-03-25_at_15.09.45.png)

Now attach the role to the freshly created user by clicking on the user. In the user detail view click on the three dots next to the user name and click "Update". In the "Roles" section click into the line and click on "Connectors" to enable the Role for the user immediately.
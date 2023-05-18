# Integrations

## Introduction

OpenCTI supports multiple ways to integrate with other systems which do not have native connectors or plugins to the platform. Here are the technical features available to ease the connection and the integration of the platform with other applications.

!!! note "Connectors list"
    
    If you are looking to the list of OpenCTI connectors or native integration, please check the [OpenCTI Ecosystem](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76).

## Native feeds and streams

To ease integrations with other products, OpenCTI has built-in capabilities to deliver the data to third-parties.

### CSV Feeds

It is possible to create as many CSV feeds as needed, based on filters and accessible in HTTP. CSV feeds are available in Data > Data sharing > Feeds (CSV).

When creating a CSV feed, you need to select one or multiple types of entity to make available. For all columns available in the CSV, you've to select which field will be used for each type of entity:

![CSV Feeds](assets/csv.png)

!!! note "Details"
    
    For more information about CSV feeds, filters and configuration, please check the [Export in structured format](../usage/export-structured.md) section.

### TAXII collections

Most of the moden cybersecurity systems such as SIEMs, EDRs, XDRs and even firewalls supports the [TAXII protocol](https://oasis-open.github.io/cti-documentation/taxii/intro.html) which is basically a paginated HTTP STIX feed. OpenCTI implements a [TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html) server with the ability to create as many TAXII collections as needed in Data > Data sharing > TAXII Collections?

TAXII collections are a sub-selection of the knowledge available in the platform and relie on filters. For instance, it is possible to create TAXII collections for pieces of malware with a given label, for indicators with a score greater than *n*, etc.

![TAXII Feeds](assets/taxii.png)

### HTTP Streams

After implementing CSV feeds and TAXII collections, we figured out that those 2 stateless APIs are definitely not enough when it comes to tackle advanced information sharing challenges such as:

* Real time transmission of the information (ie. avoid hundreds of systems to pull data every 5 minutes).
* Dependencies resolution (ie. an intrusion created by an organization but the organization is not in the TAXII collection).
* Partial update for huge entities such as report (ie. just having the *update* event).
* Delete events when necessary (ie. to handle indicators expiration in third party systems for instance).

Live streams are available in Data > Data sharing > Live streams. As TAXII collections, it is possible to create as many streams as needed using filters.

![Streams](assets/streams.png)

Streams implement the [HTTP SSE (Server-sent events)](https://en.wikipedia.org/wiki/Server-sent_events) protocol and give applications to consume a real time pure STIX 2.1 stream. Stream connectors in the [OpenCTI Ecosystem](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76) are using live streams to consume data and *do* something such as create / update / delete information in SIEMs, XDRs, etc.

### Authentication

For all previously explained capabilities, as they are over the HTTP protocol, 3 authentication mechanisms are available to consume them.

1. Using a bearer header with your OpenCTI API key

	```
	Authorization: Bearer a17bc103-8420-4208-bd53-e1f80845d15f
	```

	!!! note "API Key"
	    
		Your API key can be found in your profile available clicking on the top right icon.

2. Using basic authentication

	```
	Username: Your platform username
	Password: Your plafrom password
	Authorization: Basic c2FtdWVsLmhhc3NpbmVBZmlsaWdyYW4uaW86TG91aXNlMTMwNCM=
	```

3. Using client certificate authentication

	To know how to configure the client certificate authentication, please consult the [authentication configuration](authentication.md) section.

## API and libraries

### GraphQL API

To allow analysts and developers to implement more custom or complex use cases, a full [GraphQL API](https://graphql.org) is available in the application on the `/graphql` endpoint.

The API can be queried using various GraphQL client such as [Postman](https://www.postman.com/) but you can leverage any HTTP client to forge GraphQL queries using `POST` methods.

#### Authentication

The API authentication can be performed using the token of a user and a classic Authorization header:

```
Content-Type: application/json
Authorization: Bearer 6b6554c4-bb2c-4c80-9cd3-30288c8bf424
```

#### Playground

The playground is available on the `/graphql` endpoint. A link button is also available in the profile of your user.

![Playground](assets/playground.png)

All the schema documentation is directly available in the playground.

![Schema](assets/playground-schema.png)

If you already logged to OpenCTI with the same browser you should be able to directly do some requests. If you are not authenticated or want to authenticate only through the playground you can use a header configuration using your profile token

Example of configuration (bottom left of the playground):

![Playground authentication](assets/playground-auth.png)

### Python library

Since not everyone is familiar with GraphQL APIs, we've developed a Python library to ease the interaction with it. The library is pretty easy to use. To initiate the client:

```python
# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = "http://opencti:4000"
api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)
```

Then just use the available helpers:
```python
# Search for malware with the keyword "windows"
malwares = opencti_api_client.malware.list(search="windows")

# Print
print(malwares)
```


!!! note "Details"
    
    For more detailed information about the Python library, please read the [dedicated section](../development/python.md).




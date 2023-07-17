# Native feeds

## Live streams

### Introduction

The best way to consume OpenCTI data, whether it is through a [stream connector](../deployment/connectors.md) or within another OpenCTI instance, is to use the live streams. Live streams are like TAXII collection (ie. serving STIX 2.1 bundles) but *under steroids*. This means that live streams are supporting:

* create, update and delete events depending on the filters ;
* caching already created entities in the last 5 minutes ;
* resolving relationships and dependencies even out of the filters ;
* they can be public (without authentication).

![Live stream](assets/live-stream.png)

### Schenario

To better understand how live streams are working, let's take a few examples, from simple to complex.

Given a live stream with filters *Entity type: Indicator* `AND` *Label: detection*. Let's see what happen with an indicator with:

* Marking definition: `TLP:GREEN`
* Author `Crowdstrike`
* Relation `indicates` to the malware `Emotet`

| Action                                              | Result in stream (`resolve-dependencies=false`)                              | Result in stream (`resolve-dependencies=true`)                                    |
| :--------------------------------------- | :------------------------------------------------------------------------- | :------------------------------------------------------------------------------ |
| 1. Create an indicator  | Nothing                                                                    | Nothing                                                                         |
| 2. Add the label `detection`          | Create `TLP:GREEN`, create `CrowdStrike`, create the indicator               | Create `TLP:GREEN`, create `CrowdStrike`, create the malware `Emotet`, create the indicator, create the relationship `indicates`                                                                    |
| 3. Remove the label `detection`       | Delete the indicator                                                    | Delete the indicator |
| 4. Add the label `detection`          | Create the indicator                                                    | Create the indicator, create the relationship `indicates`  |
| 5. Delete the indicator               | Delete the indicator                                                    | Delete the indicator |

## TAXII Collections

OpenCTI has an embedded TAXII API endpoint which provides valid STIX 2.1 bundles. If you wish to know more about the TAXII standard, [please read the official introduction](https://oasis-open.github.io/cti-documentation/taxii/intro.html).

In OpenCTI you can create as many TAXII 2.1 collections as needed. Each of them can have specific filters to publish only a subset of the platform overall knowledge (specific types of entities, labels, marking definitions, etc.).

![TAXII Collection](assets/taxii-collection.png)

After creating a new collection, every systems with a proper access token can consume the collection using different kinds of authentication (basic, bearer, etc.)

As when using the GraphQL API, TAXII 2.1 collections have a classic pagination system that should be handled by the consumer. Also, it's important to understand that element dependencies (nested IDs) inside the collection are not always contained/resolved in the bundle, so consistency needs to be handled at the client level.

## CSV feeds

OpenCTI is able to publish data in CSV feeds on a rolling period.
# Data model

This page tells you where to find the reference of the OpenCTI data model: the types of entities, observables and relationships, and the attributes of each type.

## What the data model is

OpenCTI stores knowledge as a graph: entities are the nodes, relationships are the edges, and both carry attributes. The model follows the [STIX 2.1 standard](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html), and OpenCTI extends it with types that STIX does not define, such as Channels, Events, Narratives or cryptocurrency wallets.

The [Data model](../usage/data-model.md) page explains these concepts, lists the STIX naming shortcuts (SDO, SCO, SRO) and the OpenCTI extensions, and shows a diagram of all the entity and relationship types.

## Where to find the reference

| What you need                                                     | Where to find it                                                                                                                                       |
|:------------------------------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| An overview of the model and a diagram of all the types           | The [Data model](../usage/data-model.md#diagram-of-types) page.                                                                                         |
| Every type, attribute, query and mutation, in one file            | The [GraphQL schema](#graphql-schema) in the OpenCTI repository.                                                                                       |
| The same schema, browsable on your own platform                   | The documentation explorer of the [GraphQL playground](../development/api-usage.md), when introspection is allowed (see the [note below](#graphql-schema)). |
| The values of the vocabularies (open lists) used by the attributes | The [Taxonomy](taxonomy.md) page.                                                                                                                      |
| The definition of the STIX objects and properties                 | The [STIX 2.1 specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).                                                          |

## GraphQL schema

The GraphQL API exposes the whole data model, so its schema is the most complete reference of the types and attributes. The full schema is printed in a single file of the OpenCTI repository: [`opencti-platform/opencti-front/src/schema/relay.schema.graphql`](https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-front/src/schema/relay.schema.graphql). The `build:schema` script of `opencti-graphql` (also run by `yarn start`) generates it, and the generated file is committed to the repository. It is built from the source definitions: [`opencti-platform/opencti-graphql/config/schema/opencti.graphql`](https://github.com/OpenCTI-Platform/opencti/blob/master/opencti-platform/opencti-graphql/config/schema/opencti.graphql) and the `.graphql` file of each module in [`opencti-platform/opencti-graphql/src/modules`](https://github.com/OpenCTI-Platform/opencti/tree/master/opencti-platform/opencti-graphql/src/modules).

The links above point to the `master` branch. To read the schema of the version you run, open the same file from the Git tag of that version.

For example, search the schema for `type Report` to read the attributes of a Report, or for `input ReportAddInput` to read the fields accepted when creating one.

!!! note "Schema documentation in the playground"

    The documentation explorer and the autocompletion of the GraphQL playground read the schema through introspection. Introspection is disabled by default: an administrator allows it by setting `app:graphql:playground:force_disabled_introspection` to `false`. The playground itself must be enabled (`app:graphql:playground:enabled`). See the [configuration](../deployment/configuration.md#technical-customization) page.

## What's next?

- Query and update the data with the [GraphQL API](api.md).
- Filter the data in queries with the [filters](filters.md) reference.

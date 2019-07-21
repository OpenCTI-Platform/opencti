---
id: version-1.0.2-model
title: Data model
sidebar_label: Data model
original_id: model
---

Even if the OpenCTI data model is based on [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro) and you are already familiar with it, you should read this section to understand how we have implemented this model and what make the OpenCTI platform unique (even if some features described here are not available in the frontend yet).

## The hypergraph

The OpenCTI data model needs a database that implements the [hypergraph theory](https://en.wikipedia.org/wiki/Hypergraph). We made this choice because we want, now and in the future, to be able to modelize the full understanding of a threat or a campaign without limitation. We selected [Grakn Core Server](http://grakn.ai) as our main database backend because it really fits our needs to implement the model we designed. Here are some useful information about the OpenCTI graph model.

### Hierarchical entities

Entities are not all at the same level, we have implemented both abstract entities (normal entities inheritates of their attributes) and sub-entities (that inheritates attributes from other entities). So for instance, we have an entity named `Stix-Domain-Entity` that has a `name` and a `description`, and an other entity `Tool` which is a child of `Stix-Domain-Entity` and has the specific attribute `tool_version`.

```
Stix-Domain-Entity sub entity,
  abstract,
  has name,
  has description;
```

```
Tool sub Stix-Domain-Entity,
  has tool_version;
```

This allow database query to select all `Stix-Domain-Entity` instances if needed, or just `Tool` instances.

### Relations

Entities could be linked by some relations. A relation is a connection between any number of entities, identified with specific `roles` that defined a relation:

```
origin sub role;
attribution sub role;

attributed-to sub relation,
  relates origin,
  relates attribution;

Threat-Actor sub Stix-Domain-Entity,
  plays origin;

Intrusion-Set sub Stix-Domain-Entity,
  plays attribution;
```

This means that you can have this relation:

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Intrusion Set (*attribution*)   | **attributed-to**    | Threat Actor (*origin*)               |

To know more about available relations, please read the [dedicated section](../reference/relations).

### 




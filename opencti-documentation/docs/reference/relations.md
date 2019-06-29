---
id: reference-relations
title: Relations between entities
sidebar_label: Relations between entities
---

## Introduction

On the OpenCTI platform, **the direction of the relations between entities matters a lot**. Either you add knowledge manually to a report or creating new knowledge programmatically, you have to be aware of the entities-relations model in order to use the platform. This model is based on [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro) so you are already familiar with it, you should already be aware of most of the following information.


## Possible relations dependending on source entity

### Threat Actor

| Source        | Role           | Relation type  | Target         | Role      |
| ------------- |----------------|----------------| ---------------|-----------|
| Threat Actor  | user           | uses           | Malware        | usage     |
| Threat Actor  | user           | uses           | Tool           | usage     |
| Threat Actor  | user           | uses           | Attack Pattern | usage     |
| Threat Actor  | source         | targets        | Sector         | target    |
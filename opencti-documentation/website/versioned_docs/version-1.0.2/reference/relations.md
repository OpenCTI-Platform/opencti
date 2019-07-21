---
id: version-1.0.2-relations
title: Relations between things
sidebar_label: Relations between things
original_id: relations
---

## Introduction

> On the OpenCTI platform, **the direction of the relations between entities matters a lot**.

Either you add knowledge manually to a report or creating new knowledge programmatically, you have to be aware of the entities-relations model in order to use the platform. This model is based on [STIX2](https://oasis-open.github.io/cti-documentation/stix/intro) so you are already familiar with it, you should already be aware of most of the following information.

![Report relation direction 1](assets/reference/report_relation_direction1.png "Report relation direction 1")

![Report relation direction 2](assets/reference/report_relation_direction2.png "Report relation direction 2")

## Possible relations from an entity

### Threat Actor

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Threat Actor (*user*)           | **uses**             | Malware (*usage*)                     |
| Threat Actor (*user*)           | **uses**             | Tool (*usage*)                        |
| Threat Actor (*user*)           | **uses**             | Attack Pattern (*usage*)              |
| Threat Actor (*source*)         | **targets**          | Vulnerability (*target*)               |
| Threat Actor (*source*)         | **targets**          | Sector (*target*)                     |
| Threat Actor (*source*)         | **targets**          | Region / Country / City (*target*)    |
| Threat Actor (*relate_from*)    | **related-to**       | All (*relate_to*)                     |

### Intrusion Set

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Intrusion Set (*attribution*)   | **attributed-to**    | Threat Actor (*origin*)               |
| Intrusion Set (*user*)          | **uses**             | Malware (*usage*)                     |
| Intrusion Set (*user*)          | **uses**             | Tool (*usage*)                        |
| Intrusion Set (*user*)          | **uses**             | Attack Pattern (*usage*)              |
| Intrusion Set (*source*)        | **targets**          | Vulnerability (*target*)              |
| Intrusion Set (*source*)        | **targets**          | Sector (*target*)                     |
| Intrusion Set (*source*)        | **targets**          | Region / Country / City (*target*)    |
| Intrusion Set (*relate_from*)   | **related-to**       | All (*relate_to*)                     |

### Campaign

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Campaign (*attribution*)        | **attributed-to**    | Threat Actor (*origin*)               |
| Campaign (*attribution*)        | **attributed-to**    | Intrusion Set (*origin*)              |
| Campaign (*user*)               | **uses**             | Malware (*usage*)                     |
| Campaign (*user*)               | **uses**             | Tool (*usage*)                        |
| Campaign (*user*)               | **uses**             | Attack Pattern (*usage*)              |
| Campaign (*source*)             | **targets**          | Vulnerability (*target*)              |
| Campaign (*source*)             | **targets**          | Sector (*target*)                     |
| Campaign (*source*)             | **targets**          | Region / Country / City (*target*)    |
| Campaign (*relate_from*)        | **related-to**       | All (*relate_to*)                     |

### Incident

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Incident (*attribution*)        | **attributed-to**    | Threat Actor (*origin*)               |
| Incident (*attribution*)        | **attributed-to**    | Intrusion Set (*origin*)              |
| Incident (*attribution*)        | **attributed-to**    | Campaign (*origin*)                   |
| Incident (*user*)               | **uses**             | Malware (*usage*)                     |
| Incident (*user*)               | **uses**             | Tool (*usage*)                        |
| Incident (*user*)               | **uses**             | Attack Pattern (*usage*)              |
| Incident (*source*)             | **targets**          | Vulnerability (*target*)              |
| Incident (*source*)             | **targets**          | Sector (*target*)                     |
| Incident (*source*)             | **targets**          | Region / Country / City (*target*)    |
| Incident (*relate_from*)        | **related-to**       | All (*relate_to*)                     |

### Malware

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Malware (*original*)            | **variant-of**       | Malware (*variation*)                 |
| Malware (*user*)                | **uses**             | Tool (*usage*)                        |
| Malware (*user*)                | **uses**             | Attack Pattern (*usage*)              |
| Malware (*source*)              | **targets**          | Vulnerability (*target*)              |
| Malware (*source*)              | **targets**          | Sector (*target*)                     |
| Malware (*source*)              | **targets**          | Region / Country / City (*target*)    |
| Malware (*relate_from*)         | **related-to**       | All (*relate_to*)                     |

### Tool

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Tool (*user*)                   | **uses**             | Attack Pattern (*usage*)              |
| Tool (*source*)                 | **targets**          | Vulnerability (*target*)              |
| Tool (*relate_from*)            | **related-to**       | All (*relate_to*)                     |

### Vulnerability

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Vulnerability (*relate_from*)   | **related-to**       | All (*relate_to*)                     |

### Sector

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Sector (*part_of*)              | **gathering**        | Sector (*gather*)                     |
| Sector (*relate_from*)          | **related-to**       | All (*relate_to*)                     |

### Organization

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Organization (*part_of*)        | **gathering**        | Sector (*gather*)                     |
| Organization (*localized*)      | **localization**     | Region / Country / City (*location*)  |
| Organization (*relate_from*)    | **related-to**       | All (*relate_to*)                     |

### Person

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Person (*part_of*)              | **gathering**        | Organization (*gather*)               |
| Person (*localized*)            | **localization**     | Region / Country / City (*location*)  |
| Person (*relate_from*)          | **related-to**       | All (*relate_to*)                     |

### Region

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Region (*relate_from*)          | **related-to**       | All (*relate_to*)                     |

### Country

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| Country (*localized*)           | **localization**     | Region (*location*)                   |
| Country (*relate_from*)         | **related-to**       | All (*relate_to*)                     |

### City

| Source (*role*)                 | Relation type        | Target (*role*)                       |
| ------------------------------- | -------------------- | ------------------------------------- |
| City (*localized*)              | **localization**     | Country (*location*)                  |
| City (*relate_from*)            | **related-to**       | All (*relate_to*)                     |

## Possible relations from a relation
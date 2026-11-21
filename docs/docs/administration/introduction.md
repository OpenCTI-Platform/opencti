# Introduction

The Administration section explains how to configure and operate an OpenCTI platform once it is deployed: platform parameters, security and access control, data segregation, customization of entity types, data mappers, activity monitoring and the connection to XTM Hub. Most of these settings are in the `Settings` menu, and each one requires a dedicated capability, described in the [Users and RBAC](users.md) page.

## Platform and license

- [Enterprise edition](enterprise.md): the features that require the OpenCTI Enterprise Edition license, and how to activate it.
- [Product life cycle](product-life-cycle.md): version numbering, the Long-Term Support (LTS) program and breaking change policies.

## Data management

- [Merging and de-duplication](merging.md): how OpenCTI merges duplicate entities.
- [CSV Mappers](csv-mappers.md) and [JSON Mappers](json-mappers.md): how to parse CSV and JSON files into STIX 2.1 objects.
- [Ingestion health](ingestion-health.md): whether each connector, feed and synchronization ingests data as expected.

## Platform settings

- [Parameters](parameters.md) (`Settings > Parameters`): the global platform settings.
    - Configuration: platform title, platform favicon URL, sender email address and third-party analytics.
    - Appearance: default theme, language, date and time format in tables, hidden entity types, and removal of the Filigran logos.
    - Platform announcements, theme customization, and the status of the dependencies and managers.
- Security:
    - [Policies](policies.md) (`Settings > Security > Policies`): platform main organization, authentication strategies, password policies, the banner, and the messages shown on the login page (platform login message, platform consent message and platform consent confirm text).
    - [Authentication](authentication-via-ui.md), [SMTP configuration](smtp-configuration.md) and [Cookies](cookies.md).
    - [Users and RBAC](users.md), [Merging users](users-merge.md) and [Protect sensitive configuration](protect-sensitive-configuration.md).
    - Data segregation: [Marking restriction](segregation.md), [Organization segregation](organization-segregation.md), [Authorized members](authorized-members.md) and [Request access](request-access.md).
    - [Dissemination list](dissemination-list.md) and [Email templates](email-templates.md).
- Customization: [Entity types](entities.md), [Custom fields](custom-fields.md), [Rules engine](reasoning.md), [Notifiers](notifiers.md), [Retention policies](retentions.md), [Decay rules](decay-rules.md), [Decay exclusion rules](decay-exclusion-rules.md), [Fintel designs](fintel-designs.md) and [Exclusion lists](exclusion-lists.md).
- [Taxonomies](ontologies.md): labels, kill chain phases, vocabularies, status templates and case templates.
- [Activity](audit/overview.md): the audit log of administration actions and knowledge access, its configuration and its triggers.
- [File indexing](file-indexing.md): full text search in the content of files.
- [Support package](support-package.md): how to generate a package to troubleshoot the platform.
- [XTM Hub](hub.md): how to connect the platform to XTM Hub.

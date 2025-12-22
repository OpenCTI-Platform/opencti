# Meaning of dates

In OpenCTI, entities can contain various dates, each representing different types of information. The available dates vary depending on the entity types.

## Dates

In OpenCTI, dates play a crucial role in understanding the context and history of entities. Here's a breakdown of the different dates you might encounter in the platform:

- “Platform creation date”: This date signifies the moment the entity was created within OpenCTI. On the API side, this timestamp corresponds to the `created_at` field. It reflects the initiation of the entity within the OpenCTI environment.
- “Original creation date”: This date reflects the original creation date of the data on the source's side. It becomes relevant if the source provides this information and if the connector responsible for importing the data takes it into account. In cases where the source date is unavailable or not considered, this date defaults to the import date (i.e. the “Platform creation date”). On the API side, this timestamp corresponds to the `created` field.
- “Modification date”: This date captures the most recent modification made to the entity, whether a connector automatically modifies it or a user manually edits the entity. On the API side, this timestamp corresponds to the `updated_at` field. It serves as a reference point for tracking the latest changes made to the entity.
- Date not shown on GUI: There is an additional date which is not visible on the entity in the GUI. This date is the `modified` field on the API. This date reflects the original update date of the data on the source's side. The difference between `modified` and `updated_at` is identical to the difference between `created` and `created_at`.

![Dates](assets/dates.png)

Understanding these dates is pivotal for contextualizing the information within OpenCTI, ensuring a comprehensive view of entity history and evolution.

## Date types

### Technical dates

The technical dates refer to the dates directly associated to data management within the platform. The API fields corresponding to technical dates are:

- created_at: Indicates the date and time when the entity was created in the platform.
- updated_at: Represents the date and time of the most recent update to the entity in the platform.

### Functional dates

The functional dates are the dates functionally significant, often indicating specific events or milestones. The API fields corresponding to functional dates are:

- created: Denotes the date and time when the entity was created on the source's side.
- modified: Represents the date and time of the most recent modification to the entity on the source's side.
- start_time: Indicates the start date and time associated with a relationship.
- stop_time: Indicates the stop date and time associated with a relationship.
- first_seen: Represents the initial date and time when the entity/activity was observed.
- last_seen: Represents the most recent date and time when the entity/activity was observed.
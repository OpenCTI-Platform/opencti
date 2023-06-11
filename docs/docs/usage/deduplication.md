# Deduplication

One of the core concept of the OpenCTI knowledge graph is all underlying mechanisms implemented to accurately de-duplicate and consolidate (aka. `upserting`) information about entities and relationships.

## Creation behavior

When an object is created in the platform, whether manually by a user or automatically by the connectors / workers chain, the platform checks if something already exist based on some properties of the object. If the object already exists, it will return the existing object and, [in some cases](), update it as well.

Technically, OpenCTI generates deterministic IDs based on the listed properties below to prevent duplicate (aka "ID Contributing Properties"). Also, it is important to note that there is a special link between `name` and `aliases` leading to not have entities with overlaping aliases or an alias already used in the name of another entity.

### Entities

| Type                    | Attributes                                                                                                     |
| :---------------------- | :------------------------------------------------------------------------------------------------------------- |
| Area                    | (`name` OR `x_opencti_alias`) AND `x_opencti_location_type`                                                    |
| Attack Pattern          | (`name` OR `alias`) AND optional `x_mitre_id`                                                                  |
| Campaign                | `name` OR `alias`                                                                                              |
| Channel                 | `name` OR `alias`                                                                                              |
| City                    | (`name` OR `x_opencti_alias`) AND `x_opencti_location_type`                                                    |
| Country                 | (`name` OR `x_opencti_alias`) AND `x_opencti_location_type`                                                    |
| Course Of Action        | (`name` OR `alias`) AND optional `x_mitre_id`                                                                  |
| Data Component          | `name` OR `alias`                                                                                              |
| Data Source             | `name` OR `alias`                                                                                              |
| Event                   | `name` OR `alias`                                                                                              |
| Feedback Case           | `name` AND `created` (date)                                                                                    |
| Grouping                | `name` AND `context`                                                                                           |
| Incident                | `name` OR `alias`                                                                                              |
| Incident Response Case  | `name` OR `alias`                                                                                              |
| Indicator               | `name` OR `alias`                                                                                              |
| Individual              | (`name` OR `x_opencti_alias`) and `identity_class`                                                             |
| Infrastructure          | `name` OR `alias`                                                                                              |
| Intrusion Set           | `name` OR `alias`                                                                                              |
| Language                | `name` OR `alias`                                                                                              |
| Malware                 | `name` OR `alias`                                                                                              |
| Malware Analysis        | `name` OR `alias`                                                                                              |
| Narrative               | `name` OR `alias`                                                                                              |
| Note                    | *None*                                                                                                         |
| Observed Data           | `name` OR `alias`                                                                                              |
| Opinion                 | *None*                                                                                                         |
| Organization            | (`name` OR `x_opencti_alias`) and `identity_class`                                                             |
| Position                | (`name` OR `x_opencti_alias`) AND `x_opencti_location_type`                                                    |
| Region                  | `name` OR `alias`                                                                                              |
| Report                  | `name` AND `publised` (date)                                                                                   |
| RFI Case                | `name` AND `created` (date)                                                                                    |
| RFT Case                | `name` AND `created` (date)                                                                                    |
| Sector                  | (`name` OR `alias`) and `identity_class`                                                                       |
| Task                    | *None*                                                                                                         |
| Threat Actor            | `name` OR `alias`                                                                                              |
| Tool                    | `name` OR `alias`                                                                                              |
| Vulnerability           | `name` OR `alias`                                                                                              |

### Relationships

The deduplication process of relationships is based on the following criterias:

* Type
* Source
* Target
* Start time between -30 days / + 30 days
* Stop time between -30 days / + 30 days

### Observables

For STIX Cyber Observables, OpenCTI also generate deterministic IDs based on the [STIX specification](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070607) using the "ID Contributing Properties" defined for each type of observable.

## Update behavior

If an entity already exists in the platform, the `attributes` may be updated by the incoming creation with the following rule:

!!! note ""
    
    If `confidence_level` of the created entity is >= (greater or equal) then the `confidence_level` of the existing entity, attributes will be updated. Obviously, the `confidence_level` will also be increased with the new one.

This logic has been implemented so the platform can converge to the highest confidence and quality levels for the entities and the relationships.
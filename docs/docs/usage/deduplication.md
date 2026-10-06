# Deduplication

One of the core concept of the OpenCTI knowledge graph is all underlying mechanisms implemented to accurately de-duplicate and consolidate (aka. `upserting`) information about entities and relationships.

## Creation behavior

When an object is created in the platform, whether manually by a user or automatically by the connectors / workers chain, the platform checks if something already exist based on some properties of the object. If the object already exists, it will return the existing object and, in some cases, update it as well.

Technically, OpenCTI generates deterministic IDs based on the listed properties below to prevent duplicate (aka "ID Contributing Properties"). Also, it is important to note that there is a special link between `name` and `aliases` leading to not have entities with overlapping aliases or an alias already used in the name of another entity.

### Entities

| Type                    | Attributes                                                  |
| :---------------------- |:------------------------------------------------------------|
| Area                    | (`name` OR `x_opencti_alias`) AND `x_opencti_location_type` |
| Attack Pattern          | (`name` OR `alias`) AND optional `x_mitre_id`               |
| Campaign                | `name` OR `alias`                                           |
| Channel                 | `name` OR `alias`                                           |
| City                    | (`name` OR `x_opencti_alias`) AND `x_opencti_location_type` |
| Country                 | (`name` OR `x_opencti_alias`) AND `x_opencti_location_type` |
| Course Of Action        | (`name` OR `alias`) AND optional `x_mitre_id`               |
| Data Component          | `name` OR `alias`                                           |
| Data Source             | `name` OR `alias`                                           |
| Event                   | `name` OR `alias`                                           |
| Feedback Case           | `name` AND `created` (date)                                 |
| Grouping                | `name` AND `context`                                        |
| Incident                | `name` OR `alias`                                           |
| Incident Response Case  | `name` OR `alias`                                           |
| Indicator               | `pattern` OR `alias`                                        |
| Individual              | (`name` OR `x_opencti_alias`) and `identity_class`          |
| Infrastructure          | `name` OR `alias`                                           |
| Intrusion Set           | `name` OR `alias`                                           |
| Language                | `name` OR `alias`                                           |
| Malware                 | `name` OR `alias`                                           |
| Malware Analysis        | `name` OR `alias`                                           |
| Narrative               | `name` OR `alias`                                           |
| Note                    | *None*                                                      |
| Observed Data           | `name` OR `alias`                                           |
| Opinion                 | *None*                                                      |
| Organization            | (`name` OR `x_opencti_alias`) and `identity_class`          |
| Position                | (`name` OR `x_opencti_alias`) AND `x_opencti_location_type` |
| Region                  | `name` OR `alias`                                           |
| Report                  | `name` AND `published` (date)                               |
| RFI Case                | `name` AND `created` (date)                                 |
| RFT Case                | `name` AND `created` (date)                                 |
| Sector                  | (`name` OR `alias`) and `identity_class`                    |
| Task                    | *None*                                                      |
| Threat Actor            | `name` OR `alias`                                           |
| Tool                    | `name` OR `alias`                                           |
| Vulnerability           | `name` OR `alias`                                           |

!!! info "Names and aliases management"
    
    The name and aliases of an entity define a set of unique values, so it's not possible to have the name equal to an alias and vice versa.

### Relationships

The deduplication process of relationships is based on the following criteria:

* Type
* Source
* Target
* Start time between -30 days / + 30 days
* Stop time between -30 days / + 30 days

Sightings use the same criteria with `first_seen` and `last_seen`. A relationship with the same standard or STIX ID is always merged, whatever its dates.

The ±30 days window is the default value. You can change it globally or per relationship type with the `relations_deduplication` parameters (see [configuration](../deployment/configuration.md#functional-customization)). `past_days` and `next_days` accept:

* a number of days, for example `30`. Decimal values are rounded to the nearest day.
* an ISO 8601 duration, for example `PT30M`, `PT6H` or `P1DT12H`. Use days and time units only: years, months and weeks have no fixed length.

The following configuration deduplicates sightings over a ±30 minutes window:

```json
"relations_deduplication": {
  "types_overrides": {
    "stix-sighting-relationship": { "past_days": "PT30M", "next_days": "PT30M" }
  }
}
```

With environment variables, set `RELATIONS_DEDUPLICATION__TYPES_OVERRIDES__STIX-SIGHTING-RELATIONSHIP__PAST_DAYS=PT30M` and `RELATIONS_DEDUPLICATION__TYPES_OVERRIDES__STIX-SIGHTING-RELATIONSHIP__NEXT_DAYS=PT30M` on every platform node.

!!! warning "Values are not validated"

    A value that is neither a number nor an ISO 8601 duration (for example `30m`) is silently ignored and gives a window of 0. After a change, check the result with a test relationship.

!!! note "How the window applies"

    * A relationship type override replaces the global configuration: a value missing from the override resolves to 0.
    * The window is compared with the dates of the stored relationship. With a ±30 minutes window, a sighting of a single event is merged only if it is less than 30 minutes away from both the `first_seen` and the `last_seen` of the stored sighting, so a stored sighting always spans less than 30 minutes. It is a sliding window, not a fixed clock grid.
    * A window of 0 does not disable deduplication: relationships with identical dates share the same standard ID and are still merged.
    * Changing the window does not split or merge relationships already stored.

### Observables

For STIX Cyber Observables, OpenCTI also generate deterministic IDs based on the [STIX specification](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070607) using the "ID Contributing Properties" defined for each type of observable.

### STIX IDs and imported objects

The `Standard STIX ID` displayed by OpenCTI is the platform's canonical STIX
identifier for the object. For imported data, this identifier may differ from the
STIX ID used by the original source, such as a TAXII feed or an external CTI
repository.

This behavior is expected when OpenCTI needs to deduplicate and consolidate
objects from multiple sources. Source STIX IDs can still be stored under `Other
STIX IDs` when available, but users should not assume that the visible
`Standard STIX ID` always matches the original source object's STIX ID.

When correlating OpenCTI data with external sources, check the object's `Other
STIX IDs` and external references (if any), especially for data
imported from TAXII feeds or third-party CTI repositories.

## Update behavior

In cases where an entity already exists in the platform, incoming creations can trigger updates to the existing entity's attributes.
This logic has been implemented to converge the knowledge base towards the highest confidence and quality levels for both entities and relationships.

To understand in details how the deduplication mechanism works in context of the maximum confidence level, you can navigate through this diagram (section deduplication):

<iframe style="border: 1px solid rgba(0, 0, 0, 0.1);" width="800" height="450" src="https://www.figma.com/embed?embed_host=share&url=https%3A%2F%2Fwww.figma.com%2Ffile%2FlVU6O39B76MJmtnzg9DbZZ%2FConfidence-Level---Documentation%3Ftype%3Dwhiteboard%26node-id%3D0%253A1%26t%3DPQWrdBF6iMGEp0bw-1" allowfullscreen></iframe>

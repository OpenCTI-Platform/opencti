# Ingestion deduplication

Ingestion deduplication lets the platform skip objects that a source sends again without any change since its last import. It works for connectors and feeds (RSS, TAXII, TAXII push, CSV, JSON). Synchronizations are never deduplicated: they replay the events of another platform, and the platform can refuse an event as older than a local change.

Many sources send the same objects at every run. The MITRE ATT&CK connector sends hundreds of Attack Patterns where only the `modified` date moved, and some feeds re-send most of their content every hour. For each of these objects, the platform resolves every reference, locks the object, looks for the existing entity and compares it field by field, only to find that nothing needs to change. Ingestion deduplication recognizes these objects as soon as they arrive and returns the existing entity instead.

!!! note "Feature flag"

    This feature is under the feature flag `INGESTION_DEDUPLICATION`. Enable it with `APP__ENABLED_DEV_FEATURES='["INGESTION_DEDUPLICATION"]'`, or in the configuration file:

    ```json
    { "app": { "enabled_dev_features": ["INGESTION_DEDUPLICATION"] } }
    ```

    When the flag is off, nothing changes in the import of data and the configuration screens are hidden.

## How it works

Deduplication is set up with **rules**. A rule applies to one user and one entity type: it says that the objects of this type imported as this user are deduplicated.

The user is the one the import runs as:

| Ingestion | User |
|---|---|
| Connector | The connector's user |
| Feed (RSS, TAXII, TAXII push, CSV, JSON) | The user configured on the feed |
| File import | The user who launched the import |

A feed without a user runs as the system user, which has no edition screen and so no Deduplication tab: give it a user to deduplicate its objects.

When an object arrives and a rule applies:

1. The platform computes a fingerprint of the object, leaving out the fields the rule excludes, such as `modified`.
2. It compares this fingerprint with the one recorded at the last import of this object by this user.
3. If they are the same, and the entity has not changed since that import, the import is skipped: the platform returns the existing entity, and nothing is written.
4. Otherwise, the object is imported as usual, and its new fingerprint is recorded with the entity's last update date.

Fingerprints are kept in Redis, one per object and per user, and expire after a delay you choose on the rule.

The fingerprint also covers the rule itself and the user settings that change what an import applies: its confidence level for this entity type, whether it can share with organizations (with Enterprise Edition), and whether it is recorded as creator. Editing the rule, or changing one of these settings, makes the next import of every object run as usual.

### When an object changes elsewhere

When an entity is updated, deleted or merged by anything other than the import, for example by an analyst in the interface or by another source, its last update date moves away from the one recorded with the fingerprint. This includes the removal of one of its references, such as a deleted label or author. The next import of this object then runs as usual, and the content from the source is applied again.

### Several sources on the same object

Each user has its own fingerprints. Two sources running as two different users are compared each with its own last import, never with the other's.

If two sources send different versions of the same object, each import changes the object and its last update date, so nothing is skipped. This is the expected behavior: an import that changes the object is never skipped.

## Entity types

Only the following entity types can be deduplicated:

| Category | Entity types |
|---|---|
| Threats | Attack Pattern, Course of Action, Malware, Tool, Intrusion Set, Campaign, Threat Actor Group, Threat Actor Individual, Infrastructure |
| Identities | Sector, Organization, Individual, System |
| Locations | Region, Country, Administrative Area, City, Position |
| Other | Data Source, Data Component, Narrative, Channel, Language, Event |

Vulnerabilities, indicators, observables, containers (reports, groupings, notes, opinions), incidents and relationships are never deduplicated. Their updates must always reach the platform. As RSS feeds create reports, deduplication has no effect on them.

## Configuration

Rules are configured on the user, in "Settings > Security > Users". Open a user, edit it, and go to the **Deduplication** tab.

The tab shows:

- the ingestions running as this user (connectors and feeds), which are all affected by its rules;
- the rules of the user, with their excluded fields and expiration.

To manage rules, you need both the **Manage credentials** and the **Manage ingestion** capabilities. Reading them requires the **Access ingestion** capability.

!!! tip "Use a dedicated user for each source"

    Rules apply to every ingestion running as the user. If several connectors or feeds share a user, they share its rules. Give each source its own user to configure them separately.

### Rule settings

| Setting | Description |
|---|---|
| Entity type | The type of objects to deduplicate. A user has at most one rule per type. The type cannot be changed afterwards: delete the rule and create a new one. |
| Excluded fields | The fields left out of the fingerprint. A change limited to these fields does not trigger a new import. Picked from the fields of the entity type. When none are given, including for a rule created through the API, `modified` and `x_opencti_modified_at` are excluded. |
| Expiration (seconds) | How long a fingerprint is kept. After this delay, the next import of the object runs even if nothing changed. Leave it empty to use the platform default. |

!!! warning "Choose an expiration longer than the interval between two runs"

    If the fingerprints expire before the source sends the same objects again, nothing is ever skipped. For a connector or a feed running every hour, an expiration of a few hours is a good start. Remember that a run is only over once the workers have processed everything it sent.

The default expiration is 86400 seconds (24 hours).

### Excluded fields

Once you have chosen the entity type, the list offers the fields of its imported data, the ones the platform compares:

- its attributes, such as `name`, `description`, `modified` or `x_opencti_modified_at`;
- its references, such as `createdBy` (the author), `objectMarking`, `objectLabel`, `externalReferences` or `killChainPhases`.

Excluding a reference means a new label or a new external reference on the source no longer triggers an import on its own.

Exclude only fields whose changes you do not need in the platform. A field that is not excluded is always compared, so a change to it is always imported.

### Changing the user of a source

Rules belong to the user, not to the connector or feed. When you change its user, the rules stay with the previous user and do not apply to the new one. The edition screen of a managed connector warns you when the current user has rules; the edition screens of feeds do not.

### Merging users

When two users are merged, the rules of the merged user are moved to the remaining user. If both users have a rule on the same entity type, the remaining user keeps its own rule.

### Deleting users

When a user is deleted, its rules are deleted with it, even while the feature flag is off.

## Monitoring

The platform exposes a Prometheus counter, `opencti_ingestion_deduplication_total`, counted for every import checked against a rule:

| Label | Values |
|---|---|
| `opencti_entity_type` | The entity type |
| `enduser_id` | The id of the user the import runs as, the one the rule belongs to |
| `opencti_deduplication_result` | `skipped` (the import was skipped) or `imported` (the object was imported and its fingerprint recorded) |

The share of `skipped` for a type and a user tells how much work deduplication saves for the sources running as this user. The first run after a rule is created is always `imported`: the fingerprints are recorded during this run.

## Limits

- Deduplication saves work on the platform. It does not reduce the size of the queue or the work of the workers: the source still sends every object, and the worker still processes it.
- The objects linked to a deduplicated object, such as its labels, kill chain phases and external references, are still sent and processed.
- Relationships are not deduplicated.
- Imports in a draft, objects created by inference rules, imports carrying files and imports carrying explicit upsert operations (`opencti_upsert_operations`) are never deduplicated.
- A form submitted by a user who can only create knowledge leaves an existing object as it is, so it is not recorded.
- An object imported while one of its references (author, marking, label...) is not in the platform yet is not recorded: its next import runs as usual, so the reference is linked once it exists.
- If a fingerprint cannot be read or written in Redis, the error is logged and the import runs as usual.
- After an import that creates the object with references (author, markings, labels...) or changes its references, the next identical import runs once more. The imports after it are skipped.

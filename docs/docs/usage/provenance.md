# Provenance and corroboration

Every piece of knowledge in OpenCTI records who said it. Each time a source creates or re-asserts an entity, an observable or a relationship, the platform keeps an assertion for that source. From these assertions, OpenCTI derives how many independent sources corroborate the knowledge, when it was last confirmed, and whether sources disagree on its values.

Provenance is available in the Community Edition. It is deterministic: no AI is involved, and it never changes the score of indicators.

## Assertions

An assertion links a piece of knowledge to one source. A source can be:

| Source kind | Meaning                                                                     |
|:------------|:----------------------------------------------------------------------------|
| Connector   | A connector, identified through the work that ingested the data              |
| Feed        | A TAXII, RSS, CSV or JSON ingestion feed, or a synchronizer of a platform    |
| Author      | The author of knowledge written by a user, when an author is set             |
| User        | A user who created, updated or confirmed the knowledge                       |
| Inference   | An inference rule of the rule engine                                         |
| Emulation   | A security coverage result sent by OpenAEV                                   |

For each source, OpenCTI keeps the first and last assertion dates, the number of times the source asserted the knowledge and the confidence it provided. When a source sends the same knowledge again, only its assertion is updated: no new history entry is written, and the modification date of the knowledge does not change.

The details of up to 200 sources are kept per element: the earliest source and the most recently active ones. Every source that ever asserted the element is still counted in its corroboration and can be used in the "Asserted by" filters.

Assertions are recorded after deduplication, on the stored object. A source asserting a duplicate of an existing entity therefore corroborates the existing entity. When entities are merged, their assertions are merged too.

!!! note "Data created before provenance tracking"

    The provenance of the knowledge created before the upgrade is rebuilt in the background by the provenance backfill, from the history and the works of the platform. Its progress is visible in "Data > Processing > Tasks", where an administrator can also restart it. Replays are idempotent: existing assertions are merged, never duplicated.

## Corroboration and freshness

From the assertions, OpenCTI derives:

- **Corroboration**: the number of distinct sources asserting the knowledge. Knowledge with a single source is flagged as single sourced.
- **Last assertion date**: the last time any source asserted the knowledge.
- **Freshness**: the number of days since the last assertion.

These values are available as columns, sorts and filters in the lists of entities and relationships ("Corroboration", "Last assertion date", "Freshness (days since last assertion)", "Single sourced", "Has source conflicts" and "Stale knowledge"). They can be used in triggers, retention policies, dashboards and CSV exports.

In investigation graphs, nodes are surrounded by a ring whose width grows with their corroboration, and relationship labels show the number of sources between brackets.

## Sources card and sources panel

As soon as a source asserted it, the overview of every entity, observable, relationship and sighting shows a "Sources" card. The card displays:

- the corroboration badge and the last assertion date;
- the five most recent sources, each with its kind, its first and last assertion dates and its confidence. A source links to the page that describes it when there is one, for instance the organization or individual of an author;
- the fields on which sources disagree.

The card is not displayed for knowledge without provenance.

The "View all", "more sources" and "Review conflicts" buttons of the card open the sources panel, which lists:

- **Sources**: every source with its kind, first and last assertion dates, number of assertions and confidence.
- **Conflicting values**: the values proposed by sources for a field that differ from the current value (see below).
- **Procedures**: for `uses` relationships, the procedures described by each source (see below).

The "Confirm still valid" button re-asserts the knowledge in your name. It adds or refreshes your own assertion and clears a stale flag.

## Source conflicts

When a source proposes a value that differs from the current value of a single-value field (for instance the description or the primary motivation), the platform keeps the current value, as the deduplication and confidence rules decide, and records the alternative value as a conflict. At most 10 alternative values are kept per field by default.

In the sources panel, a user allowed to update the knowledge can:

- **Adopt this value**: replace the current value with the alternative value. The value previously in place becomes an alternative of its source.
- **Dismiss**: remove the alternative value.

Very large values cannot be adopted from the panel and must be edited directly.

Dates, counters, scores, confidence and technical fields never produce conflicts. Outdated conflicts can be purged automatically with a retention policy whose scope is "Source conflicts": the elements are kept, and only the conflicting values that no source re-asserted during the retention period are purged.

## Procedures

When several sources describe how a threat uses a technique, each `uses` relationship keeps the procedure provided by every source instead of overwriting the description. The "Use as description" action of the sources panel makes a procedure the description of the relationship.

Two parameters are available in the "Procedures" card of "Settings > Parameters":

- **Procedures preservation on uses relationships**: enable or disable the preservation of the procedures (enabled by default).
- **Procedures description policy**: when a new procedure arrives, keep the longest one or the most recent one as the description (longest by default).

## Curation tabs

The "Data > Curation" hub gathers the data-quality views of the platform. Provenance adds two tabs to it:

- **Conflicts**: the entities, relationships and sightings with source conflicts, with direct access to their sources panel to adopt or dismiss the alternative values.
- **Stale knowledge**: the entities, relationships and sightings flagged as stale by a [knowledge decay rule](../administration/decay-rules.md#knowledge-decay-rules), with direct access to their sources panel to confirm them.

Once the sources panel of a row is closed after a change, the list is refreshed: a row whose conflicts are all resolved, or which is confirmed, leaves the tab.

## Widgets

Two visualizations are available in the widget catalog of dashboards, for the entities and the relationships perspectives. Both honor the filters of the widget and the dates of the dashboard:

- **Freshness distribution**: the knowledge per time elapsed since its last assertion by any source (less than a month, 1 to 3 months, 3 to 6 months, 6 months to a year, more than a year, never asserted).
- **Single sourced share by type**: per entity or relationship type, the knowledge asserted by a single source versus the corroborated knowledge. The "Number of results" parameter limits the number of types displayed.

## Notifications

Two trigger event types are dedicated to provenance in [live triggers](notifications.md#triggers):

- **Corroboration reached**: notifies when the number of sources of a matching element reaches the configured threshold (2 by default, up to 200).
- **Source conflict detected**: notifies when a source proposes a value conflicting with the current value of a matching element.

## STIX export

Provenance travels in STIX bundles, streams and exports as a summary only, in the extension `extension-definition--283daa2f-7739-5345-a110-19d73676f670`:

```json
{
  "extension_type": "property-extension",
  "corroboration_count": 3,
  "assertions_count": 12,
  "first_asserted": "2026-01-12T09:30:00.000Z",
  "last_asserted": "2026-09-30T18:02:00.000Z",
  "single_sourced": false,
  "has_conflicts": true,
  "conflicting_fields": ["description"],
  "freshness_stale": false,
  "sources_by_kind": { "connector": 2, "feed": 0, "author": 0, "user": 1, "inference": 0, "emulation": 0 }
}
```

Source names and identifiers never leave the platform. The extension is computed by the platform and ignored on import. `corroboration_count` and `single_sourced` count every source of the element. `assertions_count` and `sources_by_kind` are computed from the sources whose details are kept.

In the Python client, `OpenCTIApiClient.get_provenance_extension(stix_object)` reads this summary from a STIX object, and `stix_object_or_stix_relationship.read_provenance(id=...)` returns the assertions, conflicts and procedures of an element.

## Configuration

| Parameter                                | Environment variable                       | Default value | Description                                                         |
|:-----------------------------------------|:-------------------------------------------|:--------------|:--------------------------------------------------------------------|
| provenance:enabled                       | PROVENANCE__ENABLED                        | `true`        | Record assertions on every write                                    |
| provenance:max_conflict_values_per_field | PROVENANCE__MAX_CONFLICT_VALUES_PER_FIELD  | 10            | Maximum number of alternative values kept for a conflicting field  |
| provenance:refresh_on_write              | PROVENANCE__REFRESH_ON_WRITE               | `false`       | Refresh the index after each provenance update, slows down writes   |

The provenance backfill and the knowledge freshness managers are described in the [managers](../deployment/advanced/managers.md) page.

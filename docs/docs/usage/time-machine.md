# Time machine and landscape changes

OpenCTI records every change made to the knowledge in its history: each update stores the patch applied to the entity and the reverse patch that undoes it. The knowledge time machine uses this history to answer "what did we know, and what changed since?":

- **View as of**: display any entity as it was at a past date.
- **Diff**: compare an entity between two dates.
- **Landscape changes**: compare a whole set of entities (for example every intrusion set targeting a sector) between two dates.
- **New since your last visit**: see what changed on an entity since you last opened it.
- **Change digests**: receive the landscape changes of a set of entities on a schedule.

All these features are available in the Community Edition. They are fully deterministic: every result is computed from the history and the knowledge, without any AI.

## Why use it?

Strategic analysts regularly need to answer questions such as "what changed about this threat actor since last quarter?". Without the time machine, the answer requires scrolling through the history of many entities. The time machine turns this work into a few clicks:

- Rewind an entity to the date of a past report to understand what was known at that time.
- Brief a quarterly change section in minutes: new techniques, new tooling, new victims, new infrastructure, confidence shifts and revocations.
- Focus your daily review on the entities that changed since your last visit.
- Get the landscape changes delivered to your notifications or your mailbox every week or every month.

## View an entity as of a date

Every entity with a **History** tab can be displayed as it was at a past date.

1. Open the **Overview** of the entity.
2. Click the clock icon **View as of** next to the tabs. The overview switches to a read-only view, and a banner reminds you of the date being displayed.
3. Pick the date:
    - type it in the **View as of** date field,
    - drag the slider, which shows a mark for every recorded change of the entity,
    - or jump between changes with **Previous change** and **Next change**.
4. Click **Back to the current knowledge** to leave the read-only view.

The view shows:

- the attributes of the entity at that date (name, description, aliases, confidence, score, markings, labels, author, external references, and so on),
- the number of relationships by type at that date,
- for containers, the number of contained objects at that date,
- a **Reconstruction** panel explaining how the view was rebuilt: from the current knowledge or from a knowledge snapshot, how many changes were replayed, and since when the history of the entity is available.

When the entity did not exist yet at the selected date, the view says so. When the entity has been deleted since, only a tombstone with the deletion date is displayed.

!!! note "Reconstruction warnings"

    A warning is displayed when the reconstruction is not exact:

    - a merge happened after the date: the attributes brought by the merged entities cannot be removed from the view,
    - too many changes happened after the date: the view stops at the oldest change that could be replayed,
    - the date is older than the replay window between two knowledge snapshots: the reconstruction relies on a long history replay,
    - too many relationship changes happened after the date (or during the period of a diff): relationship counts and changes only cover the most recent part of the history.

## Compare two dates with the Diff tab

The **Diff** tab of an entity shows everything that changed between two dates.

1. Open the **Diff** tab of the entity.
2. Choose the period: last 7 days, last 30 days, last 90 days, last year, quarter to date, previous quarter, or a custom period with the **From** and **To** dates.
3. Review the changes:
    - **Summary**: number of changed attributes, relationships added, removed and revoked, confidence and score evolution, confidence changes on relationships and, for containers, objects added and removed.
    - **Attributes**: the value before and after the period for every changed attribute, with the date and the author of the last change and the number of changes in the period.
    - **Relationships**: every relationship added, removed, revoked, unrevoked or whose confidence changed, with the related entity, the date and the author.
    - **Contained objects**: for containers (reports, groupings, cases...), the objects added to and removed from the container.

The period is kept in the URL of the page, so you can share a diff with a colleague, who sees it with their own rights.

!!! note "Long periods"

    The relationship list shows the 500 most recent changes. The counters of the summary always cover the whole period.

### Export a diff

Click **Export** on the Diff tab to download the diff:

| Format | Content |
|--------|---------|
| JSON   | The complete diff, for automation or archiving. |
| CSV    | One line per changed attribute, relationship or contained object. Values that could be interpreted as spreadsheet formulas are neutralized. |
| PDF    | A printable change report generated by the built-in PDF export of the platform. |

If you have the capability to upload knowledge files, you can also save the export in the files of the entity (**Data** tab) instead of downloading it.

## Landscape changes

The **Landscape changes** page compares a whole set of entities between two dates.

1. Go to **Analyses > Landscape changes**.
2. Choose the scope:
    - **Filters**: build filters on the fly (for example intrusion sets targeting the Finance sector),
    - **Saved filter**: reuse a filter set saved in a list; the entity type of the list is used,
    - **Custom view**: use every entity of the type targeted by a custom view.
3. Optionally restrict the **Entity types** and choose how to **Group by** the results: entity type, relationship type or tactic.
4. Choose the period.
5. Click **Compute the landscape changes**.

The computation runs in the background and a progress bar shows the entities already processed. The result stays available for one hour: its identifier is kept in the URL of the page, so you can come back to it while it is valid.

The result contains:

| Section | Content |
|---------|---------|
| Key figures | Entities in scope, entities changed, new entities, new relationships, removed relationships, revocations, confidence changes, score changes, new infrastructure and new indicators. |
| New techniques by tactic | Attack patterns newly linked with a `uses` relationship, grouped by tactic (kill chain phase). |
| New malware and new tools | Malware and tools newly linked with a `uses` relationship. |
| New victims | Sectors, countries and regions newly linked with a `targets` relationship. |
| New infrastructure | Infrastructures, IP addresses, domain names, URLs and hostnames newly related to the entities. |
| New relationships by type | All relationships created in the period, by relationship type. |
| Top changed entities | The changed entities, ranked by a change score that weighs new, removed and revoked relationships, changed attributes, creation and revocation in the period, and confidence and score shifts. |

Click an entity in **Top changed entities** to open its **Diff** tab on the same period. Click **Export** to download the landscape changes in JSON, CSV or PDF.

!!! note "Limits"

    The scope is the set of entities you track today: the entities that currently match the filters (or the saved filter, or the custom view) and that were created before the end of the period. Filters are evaluated on the current knowledge, and entities deleted since are not part of the scope. To keep the platform responsive, a landscape diff covers at most 1,000 entities (the most recently created first) and 20,000 new relationships; when a limit is reached, the result is flagged as partial. Each user can run one landscape diff at a time. These limits are configurable (see [Configuration](#configuration)).

### Landscape widgets

Three widget visualizations bring the landscape changes to your [custom dashboards](dashboards.md):

- **New relationships by type**,
- **New techniques by tactic**,
- **Top changed entities**.

Create them with the **Entities** perspective: the filters of the widget define the set of entities, and the period of the dashboard defines the dates (the last 30 days when the dashboard has no period). Widgets cover at most 200 entities and their result is cached for one hour. See [Widget creation](widgets.md) for details.

!!! note "Public dashboards"

    Landscape widgets are not rendered in public dashboards: a landscape diff is an expensive computation that anonymous visitors must not be able to trigger.

## New since your last visit

When you open the overview of an entity, the platform records your visit. These markers are private: only you can see them.

- On the overview, chips show what changed since your previous visit: new relationships, updates and, for containers, new contained objects. Hover the chips to see the date of your last visit.
- In lists, a small dot appears on the rows of the entities that changed since your last visit. Hover it to see the details.

A visit session lasts 30 minutes: reopening an entity within that time does not reset the reference date, so the chips stay meaningful while you work on the entity.

You can purge your markers at any time from your profile (**Last visit markers** > **Purge my last visit markers**). Administrators with the capability to manage access can purge the markers of a user from **Settings > Security > Users**, in the menu of the user (**Purge the last visit markers**); this action is recorded in the audit log. Markers expire after one year and are removed when the user is deleted.

## Change digests

A change digest sends you, at each period, the landscape changes of a set of entities: new relationships, removals, revocations, confidence and score changes. Change digests are created from the **Triggers** tab of your notifications. See [Change digests](notifications.md#change-digests).

## Access control

The time machine never bypasses markings or organization restrictions:

- The time machine is only available on entities you can access today: restricting an entity also restricts its past versions.
- Every view is computed with your current rights. If, at the selected date, the entity had markings or a sharing you do not have access to, the view only says that the entity was restricted.
- Related entities you cannot access are displayed as **Restricted**, without their name.
- Entities deleted since are displayed as tombstones (**Deleted**).
- A landscape diff is computed with the rights of the user who requested it and is only visible to that user.
- A change digest is computed with the rights of each recipient.

## History retention and knowledge snapshots

The time machine relies on the history of the knowledge:

- The history is written by the [history manager](../deployment/advanced/managers.md#history-manager), which must be enabled.
- When a **History** [retention rule](../administration/retentions.md) is active, history entries older than the retention duration are deleted. An entity can then only be rebuilt with the changes still available: older states only reflect the remaining history. The time slider and the **Reconstruction** panel show since when the history of the entity is available.

To keep the reconstruction fast, the [knowledge snapshot manager](../deployment/advanced/managers.md#knowledge-snapshot-manager) takes a compact snapshot of every entity that changed during the week: its attribute values and the identifiers of its relationships by type. A reconstruction starts from the closest snapshot (or the current knowledge) and replays the history from there, within a bounded window. Snapshots follow the history retention: they are deleted with the shortest active History retention rule.

!!! warning "Retention and the time machine"

    Shortening the History retention also shortens how far back the time machine, the Diff tab, the landscape changes and the change digests can look. Choose a History retention covering the periods your analysts compare (for example at least one year for year-over-year landscape changes).

## Configuration

The time machine works out of the box. Administrators can tune its limits with the `time_machine` and `snapshot_manager` configuration keys described in the [configuration page](../deployment/configuration.md#time-machine).

## What's next?

- [Notifications and alerting](notifications.md) to schedule change digests.
- [Custom dashboards](dashboards.md) and [Widget creation](widgets.md) to add landscape widgets.
- [Retention policies](../administration/retentions.md) to align the history retention with your analysis periods.

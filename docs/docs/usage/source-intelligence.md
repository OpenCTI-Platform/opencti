# Source intelligence

Source intelligence measures the operational value of everything that feeds your platform: connectors, ingestion feeds, authors and analysts. It answers questions such as "which feeds bring knowledge nobody else brings?", "which ones are mostly noise?", "what does each actionable object cost us?" and "which priority intelligence requirements are not covered by any source?". It then turns these answers into recommendations to tune collection.

You can find it in **Integrations > Sources**. Viewing sources requires the capability to access connectors or ingestion. Editing them (cost, settings, recommendations) requires the capability to manage connectors or ingestion.

!!! note "Enterprise Edition"

    Scorecards, the overlap matrix, the cost per actionable object and the dashboard perspective are available in every edition. The PIR relevance metric, collection gaps, recommendations and the autonomy policy are part of the [Enterprise Edition](../administration/enterprise.md).

## Sources

A source is created automatically by the source intelligence manager for:

- each **connector** registered on the platform,
- each **ingestion feed** (TAXII, RSS, CSV, JSON), mapped to the technical connector that runs it,
- each **author** (`created_by`) with a significant volume of knowledge over the last 90 days,
- each **analyst** writing knowledge directly, outside of any connector or feed.

The minimum volume and the maximum number of author and analyst sources are configurable. When a connector or a feed is deleted, its source and its scorecards are removed. What you set on a source (cost, description, tags, owner, enabled) is kept across computations.

Connector health (status, queue, errors) is not duplicated here: the scorecard page links to the connector or feed in the integrations monitoring screens.

### How facts are attributed to sources

When [provenance tracking](reliability-confidence.md) records the sources that asserted every fact (first and last assertion per source), scorecards use these assertions: a fact asserted by three connectors counts for the three of them, and lead time is exact. The status header then shows **Provenance: assertions**.

Otherwise, the platform falls back to the creators and the author of each object (**Provenance: creators**). Lead time is then approximated.

## Scorecards

Every source has a scorecard over three rolling windows: 7, 30 and 90 days. The 30-day window is the reference used by the leaderboard. A daily snapshot is kept to draw trends, and the history is backfilled over the first days after the feature is enabled.

| Metric | Meaning |
|---|---|
| Volume | Objects and relationships asserted by the source in the window, with the split per kind and the new objects. |
| Unique contribution | Share of its objects that no other source asserted. |
| Corroboration rate | Share of its objects also asserted by other sources (2 other sources by default). |
| Lead time | For the objects shared with other sources, how many hours earlier (positive) or later (negative) the source reported them, and the share of objects it reported first. |
| Accuracy | Share of its evaluated objects that were not revoked, not negatively sighted, not labelled as false positives and not excluded by a decay exclusion rule. |
| Relevance (EE) | Share of its objects matching at least one PIR. |
| Impact | Detection impact on a 0-100 logarithmic scale. Hunt true positives and incidents weigh 3, security platform sightings weigh 2, other sightings weigh 1. |
| Noise | Share of its objects that are never referenced, never sighted or expired. |
| Freshness | Hours since its last assertion, and median ingestion latency. |
| Cost per actionable object | When a cost is set, the cost over the window divided by the number of actionable objects (objects that are neither noise nor revoked, negatively sighted or flagged as false positives). |
| Community uniqueness | When Threat Pulse is available, share of its objects not known by the community. |

The **operational value score** (0-100) is the weighted average of unique contribution, first-reporter share, accuracy, relevance, impact and the inverse of noise. Default weights are 25, 15, 20, 15, 15 and 10 percent. Metrics that cannot be computed for a source (for example lead time when it shares nothing) are left out and the remaining weights are rescaled. The weights are configurable.

Indicator scores and their decay are not changed by source intelligence: scorecards only read the knowledge.

### Leaderboard and scorecard page

The **Leaderboard** tab lists the sources with their value score and their main metrics. You can sort, filter and search the list. Click a source to open its scorecard page:

- the value score with its components,
- trends of any metric over the selected window,
- the sources it overlaps with the most,
- its cost and the cost per actionable object,
- its open recommendations (EE),
- a switch to exclude the source from the computation.

The **Sources** card of an entity, an observable or a relationship (see [Provenance and corroboration](provenance.md)) links each connector, feed, author and analyst to its scorecard page. An author without a scorecard (below the minimum volume, or when you cannot access the Sources area) opens the author entity instead.

### Cost

Set a cost on a source (amount, ISO 4217 currency, per month, quarter or year) from its scorecard page. The cost is normalized to each window to compute the cost per actionable object.

### Overlap

The **Overlap** tab shows a heatmap of the sources sharing the most knowledge over the selected window. Each cell gives the number of shared objects, the share of each source and the Jaccard index. A source whose knowledge is almost entirely asserted by another one is a candidate for retirement.

## Collection gaps (EE)

The **Collection gaps** tab checks every criterion of every [PIR](pir.md) against the knowledge collected recently. For each criterion, the coverage score (0-100) combines:

- volume (40%): relationships matching the criterion over the last 30 days, against a target of 50,
- diversity (40%): distinct sources contributing to it, against a target of 3,
- freshness (20%): share of the 90-day matches that are recent.

A criterion below the coverage threshold (50 by default) is a gap. For each gap, the platform shows the sources covering it and recommends connectors from the XTM Hub catalog whose declared coverage (object types, sectors, regions) matches the criterion. The platform must be registered on the XTM Hub for catalog recommendations. A recommended connector available in the local catalog as a managed connector can be deployed in one click through XTM Composer; the deployment runs as an "Add a connector" recommendation, so it is recorded in the recommendations inbox with its audit trail and can be reverted. Other recommended connectors open in the catalog.

## Recommendations (EE)

The manager turns scorecards and gaps into recommendations. They are listed in the **Recommendations** tab and on the scorecard page of each source.

| Recommendation | Proposed when | Applying it |
|---|---|---|
| Lower confidence | Accuracy is below 70% | Lowers the max confidence of the source user by one step (15 by default). |
| Raise confidence | Accuracy is above 95% and at least 50% of its objects are corroborated | Raises the max confidence of the source user by one step. |
| Quarantine | Accuracy is below 40% | Routes the new knowledge of the source into a draft for review. |
| Add a decay rule | More than 60% of its objects are noise and it provides indicators | Creates a shorter decay rule (30 days by default) for its indicators. |
| Add a deny list | At least 10 of its objects are labelled as false positives | Creates an exclusion list with these values. |
| Change schedule | No new assertion for 72 hours although the source usually produces data | Runs the feed or managed connector more often. |
| Retire | At least 90% of its knowledge is also asserted by another source and it brings less than 5% unique objects | Stops the feed or managed connector, or disables the source. |
| Add a connector | A collection gap is detected | Deploys the recommended catalog connector. |

Sources below a minimum volume (50 objects) do not get recommendations. All thresholds are configurable.

For each recommendation you can:

- **Apply** it. Applying requires the capability matching the action (for example, managing accesses to change a user confidence level).
- **Dismiss** it, with an optional reason. A dismissed recommendation is not proposed again before a cooldown (30 days by default).
- **Revert** it once applied. Reverting restores the previous state (confidence level, schedule, connector status) and removes what was created (decay rule, exclusion list). A quarantine draft is kept for review.

A recommendation that no longer matches the situation is withdrawn automatically. Every application, dismissal and revert is recorded in the [activity logs](../administration/audit/configuration.md).

### Autonomy policy

In the settings, an administrator can allow some recommendation kinds to be applied automatically, with a maximum number of automatic actions per run. Automatically applied recommendations are flagged as such and can be reverted like the others.

## Dashboards

Dashboard widgets can use the **Sources** perspective to display any scorecard metric: number, list, distribution, horizontal bars, donut, time series and bubble chart (for example volume against value score). The dashboard time range selects the 7, 30 or 90-day window.

Click **Create the Intelligence ROI dashboard** in the Sources header to create a ready-made dashboard with the main metrics. Sources widgets are not available in public dashboards.

## Settings

The **Settings** tab gives access to:

- the computation: on or off, daily recompute hour (UTC), history backfill, snapshot retention, maximum number of scanned objects, false positive labels, corroboration and overlap parameters, author and analyst discovery,
- the value score weights,
- the recommendation thresholds and tuning steps,
- the autonomy policy and the collection gap parameters (EE).

Scorecards are computed once a day. Use **Recompute** in the Sources header to request a computation in the next minutes after a change.

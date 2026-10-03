# Incident and case timeline

## Overview

Every Incident, Incident Response, Request for Information and Request for Takedown has a timeline that tells the story of the case in time. OpenCTI assembles it automatically from the knowledge the container holds, keeps it current as the case evolves, and lets analysts add milestones, pin, hide and annotate events. The timeline is deterministic: it is computed from the platform data only, without any AI, and is available in the Community Edition.

The timeline answers questions that lists cannot: when did the adversary act, when was the activity first detected, when did the response start, when was the threat contained, and how long did it take to close the case.

## Where to find it

- **Timeline tab**: on the Incident, Incident Response, Request for Information and Request for Takedown pages, after the Content tab.
- **Overview strip**: a compact view on the overview of the same pages, with the case anchors and an **Open the timeline** link.
- **Widget**: the **Incident and case timeline** visualization in custom dashboards and custom views (see [Dashboards and custom views](#dashboards-and-custom-views)).

## What the timeline shows

### Lanes

Events are organized in lanes, from the adversary to the response:

| Lane | Content |
|:-----|:--------|
| Adversary | Techniques used (in kill chain order), first and last seen of malware, tools, infrastructures, threats and incidents, observation windows of observed data, sightings that are not from a security platform |
| Detection | Sightings from security platforms, security coverage results, hunt runs, indicator deployments, detection milestones |
| Response | Opening of the case, tasks created, due and completed, workflow status transitions, assignments, notes, opinions, investigation steps |
| Evidence | Indicators validity windows, reports and external references published, files uploaded, investigation findings about elements outside the case |
| Knowledge | Objects added to the case, relationships created, merges |
| Custom | Analyst milestones that do not belong to another lane |

### Derived events

Derived events are computed from the knowledge of the case by a set of derivation rules. They never modify the knowledge: the only data written are the timeline events, the timeline settings and the anchors of the container.

| Source | Events |
|:-------|:-------|
| Attack patterns in the case | One event per technique, with the exact window of its `uses` and `targets` relationships when they have start and stop times, otherwise placed in kill chain order with an approximate precision |
| Observed data | Observation window (first and last observed) |
| Sightings | Sighting window; sightings from a security platform land in the detection lane, the others in the adversary lane |
| Incidents, infrastructures, malware, tools, intrusion sets, threat actors, campaigns | First seen and last seen |
| Indicators | Validity window (valid from, valid until) |
| Reports and external references | Publication |
| Files of the container | Upload |
| Case | Opening |
| Tasks | Creation, due date and completion (a completed task labelled `containment` records the containment) |
| History of the container | Workflow status transitions, assignees and participants added, objects added, merges |
| Relationships between objects of the case | Creation |

The following sources are used when they exist on the platform, and are otherwise ignored:

| Source | Events |
|:-------|:-------|
| Security coverage results (OpenAEV) | Coverage results of the container, in the detection lane |
| Hunt runs | Runs of the hunts linked to the case, in the detection lane |
| Indicator deployments | Deployments of the indicators of the case on security platforms, in the detection lane |
| Case Autopilot investigation runs | One **Investigation step** per run (from start to completion) and one per goal plan action that found something, in the response lane; findings about elements outside the case appear in the evidence lane with an approximate precision |

### Precision

Each event carries a precision: **Exact**, **Hour**, **Day** or **Approximate**. Approximate events (for example techniques without dated relationships) are drawn with a dashed outline and flagged in the list view.

## Anchors

The timeline computes per-case anchors, displayed on the overview strip and at the top of the Timeline tab:

| Anchor | Definition |
|:-------|:-----------|
| First adversary activity | First event of the adversary lane |
| First detection | First event of the detection lane (security platform sightings, coverage results, hunts, deployments, detection milestones) |
| First response | First event of the response lane |
| Containment | First containment milestone, or completion of a task labelled containment |
| Closure | Last transition to the final workflow status, while the case stays closed |

Hidden events never move an anchor. Click an anchor to center the timeline on it.

The anchors are stored on the container in the `x_opencti_timeline_anchors` attribute, with two technical dates: `computed_at` (last computation) and `changed_at` (last change of one of the anchor values). They can be used to filter and sort the lists of incidents and cases (for example "Containment" before a date), and `changed_at` lets integrations fetch only the containers whose anchors changed since their last synchronization. OpenCTI does not aggregate them into metrics.

## Working with the timeline

### Views and navigation

- **Lanes view** and **List view**: the switch is always visible. The list view is a vertical, accessible list of events.
- **Zoom window**: Fit, Day, Week, Month, Quarter or Year. In the lanes view, use `+` and `-` to zoom, the left and right arrows to pan and `0` to fit.
- **Group by**: hour, day or week.
- **Search** and filters: lanes, event kinds, event source (all events, derived from the knowledge or analyst milestones), **Pinned only** and **Show hidden events**.
- The current view (filters, zoom, grouping, mode) is kept in the URL, so that a view can be shared with a link.
- The latest 500 events matching the filters are loaded first and displayed in chronological order; **Show earlier events** loads the previous ones. A link to an older event loads the earlier events until it is reached.
- In the list view, use the up and down arrows to move between events, `Enter` to open an event, `P` to pin and `H` to hide it.

### Live updates

The timeline listens to the changes of the case. When events are added or updated while you are looking at it, a **New updates** badge appears in the toolbar: click **Refresh** to load them. The platform regenerates the timeline of a case a few seconds after any change of the case or of its objects, and runs a nightly consistency pass. Users who can update the case can also use **Regenerate the timeline**.

### Event details

Click an event to open its details: time, end time, precision, lane, kind, source, author and the element it comes from. From there you can open the element (pivot) or center the timeline on the event.

### Pin, hide and annotate

- **Pin** keeps an event highlighted and available through the **Pinned only** filter.
- **Hide** removes an event from the default view (use **Show hidden events** to see it again). Hidden events never move an anchor.
- **Annotate** adds the analyst context of an event.

Derived events follow the knowledge of the case: they can be pinned, hidden and annotated, but not edited or deleted. Pins, hidden flags and annotations survive every regeneration.

### Milestones

Use **Add milestone** to record what the knowledge cannot tell: "containment", "regulator notified", "recovery completed". A milestone has a title, a time, an optional end time, a precision, a lane, a kind (Milestone, Containment, Eradication, Recovery or Notification), a description and markings, and can be pinned at creation. A **Containment** milestone records the containment anchor.

Milestones can be edited and deleted by the users who can update the case.

### Timeline settings

**Timeline settings** (in the toolbar of the tab) opens a drawer with the settings of the case timeline: enabled lanes, default grouping, default zoom window and kinds hidden by default. These settings apply to every user of the case timeline.

## Exports

- From the toolbar of the Timeline tab, **Export the timeline** downloads the current view as **CSV**, **PDF**, **SVG** or **PNG**.
- From the export menu of the container, the **Incident and case timeline** export generates the timeline as PDF, CSV, PNG or SVG and stores it in the files of the entity, like the other exports (see [Manual export](export.md)).

The CSV contains one line per event with its time, end time, lane, kind, precision, title, element, source and annotation. The PDF contains the timeline drawing, the anchors and the list of events. An export only contains the events the exporting user can see.

## Dashboards and custom views

The **Incident and case timeline** visualization is available in the widget catalog (see [Widget creation](widgets.md)):

- in custom dashboards, select the incident or case, the lanes to display (all when none is selected) and the time window;
- in the custom views of incidents and cases, the widget shows the timeline of the displayed entity.

Incident and case timelines are not available in public dashboards.

## Notifications

Two event types are available in live triggers and digests (see [Notifications and alerting](notifications.md)):

- **Timeline anchor changed**: an anchor of an incident or case moved, for example when the containment is recorded or the case is closed.
- **Timeline milestone added**: an analyst or an integration added a milestone.

The trigger filters apply to the incident or case, and only users who can access it (and the milestone) are notified.

## Access and security

- Timeline events inherit the markings and authorized members of the container, and the markings of the element they come from. Users only see the events of the elements they can access, in the timeline, the widget and the exports.
- Reading the timeline requires access to the container. Adding milestones, pinning, hiding, annotating, changing the settings and regenerating require the capability to update knowledge and edit access to the container.

## Exchange and API

- **STIX**: the analyst contributions (milestones, pins, hidden flags, annotations) travel with the container in the `extension-definition--e1c8c28f-24a5-52b1-9c2e-f3b1ff208fdb` extension. Derived events are not exported: the receiving platform computes them from its own knowledge, and imports the contributions idempotently.
- **GraphQL API**: `containerTimeline`, `containerTimelineSummary`, `containerTimelineExport`, `timelineEvent`, `timelineAnchors`, the mutations `timelineEventAdd` (with an `external_id` idempotency key), `timelineEventEdit`, `timelineEventDelete`, `timelineEventPin`, `timelineEventHide`, `timelineSettingsUpdate`, `timelineRegenerate`, and the subscription `containerTimelineUpdated`.
- **Python client (pycti)**: `OpenCTIApiClient.timeline_event` with `create`, `update`, `delete`, `list`, `read`, `pin`, `hide`, `anchors` and `regenerate`, so that connectors and incident importers can push milestones.

## Large cases

To protect the platform, the timeline of a case is built from a bounded number of objects, related elements and history entries, and keeps a bounded number of events. When a case reaches these limits, the Timeline tab displays a message and the derived events are kept by lane (adversary, detection, response, evidence, knowledge) then by time; analyst milestones are always kept. The limits and the timeline manager can be tuned in the [configuration](../deployment/configuration.md) (`timeline_manager` section).

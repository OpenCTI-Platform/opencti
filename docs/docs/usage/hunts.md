# Hunts

Hunts turn threat intelligence into searches executed in your own telemetry. A hunt states a hypothesis ("if this intrusion set is active in our environment, encoded PowerShell commands run on our endpoints"), carries the detection logic that tests it, and is executed by hunt connectors against the security platforms (SIEM, EDR, XDR, data lakes) your organization operates. Every execution is a **hunt run**: it records what was searched, where, over which time window, what was found and the resulting **verdict**.

Hunts live in the **Defense** area of the navigation, under **Hunts**.

## Concepts

| Concept | Description |
|---|---|
| Hunt | The hypothesis and its logic: a [Sigma](https://sigmahq.io/) rule and, optionally, native queries per platform. A hunt is linked to the techniques (Attack Patterns) it covers, to the threats it targets (Intrusion Sets, Malware, Campaigns, Threat Actors) and to its sources (Indicators, Reports). |
| Hunt run | One execution of a hunt by one hunt connector against one security platform over a time window. |
| Hunt connector | A connector of type `INTERNAL_HUNT` executing hunts on one platform (Splunk, Microsoft Sentinel, Elastic Security, CrowdStrike Falcon LogScale, Google SecOps, OpenSearch, Internet infrastructure tracking). See [Hunt connectors](hunt-connectors.md). |
| Verdict | The conclusion of a run: `pending`, `true_positive`, `benign` or `inconclusive`. |

### Hunt types

- **Telemetry** hunts search the logs and events of your security platforms. They require a valid Sigma rule; hunt connectors translate it into the platform language (SPL, KQL, ES|QL, LogScale, YARA-L, PPL), unless a native query is provided for that platform, in which case the native query is executed verbatim.
- **Infrastructure** hunts search the Internet for the infrastructure of a threat (servers, certificates, domains) through the infrastructure tracking connector. They do not carry a Sigma rule.

### Hunt statuses

| Status | Behavior |
|---|---|
| Draft | The hunt is being designed or awaits validation. It can be previewed but never executes. Hunts proposed by an agent or imported for review start as drafts. |
| Active | The hunt executes manually and, when configured, automatically. |
| Paused | Automatic execution is suspended. Manual runs remain possible as long as the hunt has its logic (a paused hunt can be saved without it, but does not run). |
| Retired | The hunt is kept for history. It never executes again. |

## Create a hunt

From **Defense > Hunts**, click the creation button and fill in:

- the name, the description and the **hypothesis**,
- the **Sigma rule**: it is validated while you type, the platform reports the parsing errors, the detection fields and the ATT&CK techniques found in its tags. Techniques found in the tags are linked to the hunt automatically,
- optional **native queries**, one per platform, executed verbatim instead of the translated Sigma rule,
- the **targets** (threats) and the **sources** (indicators, reports) of the hunt,
- the **time window** searched by each run (24 hours by default),
- the **expected observables**: the observable types the hunt connectors may extract from the results to create knowledge (IP addresses, domain names, URLs, file hashes, email addresses),
- the **benign patterns**: known legitimate activity, shared with the triage agent,
- the **escalation threshold**: from this number of hits, a completed run proposes an Incident (see below),
- the **scope**: the security platforms the hunt runs on (all the platforms served by a hunt connector when empty).

You can also start a hunt from a threat: the **Hunt this** action of the more actions menu of Attack Patterns, Intrusion Sets, Malware, Reports, Indicators and Priority Intelligence Requirements opens the creation form prefilled with the entity.

## Run a hunt

- **Run now** executes the hunt on every security platform of its scope, each through the hunt connector registered for it. Each platform gets its own run.
- **Test query** asks one hunt connector to translate the logic without executing it: the translated query is displayed in the **Logic** tab. Use it to review what will be executed on a platform before the first run.

Runs follow the statuses `queued`, `running`, then `completed`, `failed` or `timeout`. A run waits in the queue while its connector is unavailable or busy (each connector has a concurrency and a daily budget). Failed and timed out runs are retried automatically with an exponential backoff. Retrying a terminated run by hand starts its next attempt at once and replaces the automatic retry planned for it, so a run is never retried twice.

Runs are visible in the **Runs** tab of the hunt and in the **Hunt runs** list. The work of each run is also listed in the connector works.

## Results, evidence and verdicts

When a run completes, the hunt connector sends to OpenCTI:

- the number of **hits** and of distinct entities,
- an **evidence sample**: the result fields with their occurrence count. Raw values are never stored: each value is hashed and only a truncated preview is kept,
- **knowledge**: a sighting of each technique and indicator of the hunt, where sighted on the security platform, and observed data referencing the observables extracted from the results (limited to the expected observable types). This knowledge carries the hunt run identifier, so it can always be traced back to the run that produced it.

Evidence can also be attached to a run later (an alert raised by the SIEM, a follow-up search): it is merged into the run without changing its verdict.

The **Evidence** tab of a hunt aggregates the evidence samples of its completed runs: one row per field and hashed value, with its total count, the runs and platforms that saw it and when it was first and last seen. It covers the 100 most recent completed runs; when the hunt has more, the run selector reads "Latest 100 of N runs" and the tab names the date its window starts. The evidence of an older run stays on the page of that run, in the **Runs** tab.

The verdict is set as follows:

| Situation | Verdict |
|---|---|
| The run completed with no hit | `benign`, set automatically |
| The run completed with hits | `pending`, until an analyst sets the verdict |
| The run failed or timed out | `inconclusive` |

When the hits reach the escalation threshold, OpenCTI creates an **Incident** in a new draft workspace, never directly in the knowledge graph. The Incident description recommends running Case Autopilot once the draft is validated, to investigate the hits and their attribution. Validating the draft makes the Incident part of the knowledge.

Analysts set the final verdict from the run, with an optional feedback. Hunt statistics (runs, hits, verdict distribution, runs per platform) are displayed on the hunt overview and are available as dashboard widgets.

## AI assistance

!!! tip "Enterprise edition"

    AI assistance for hunts is available under the **OpenCTI Enterprise Edition** licence and requires XTM One. Please read the [dedicated page](../administration/enterprise.md) for full details.

- **Plan a hunt**: from the **Ask AI** menu of a threat, a report or an indicator, the hunt planner agent of XTM One designs a hunt (hypothesis, Sigma rule, native queries, benign patterns, threshold) from the knowledge about the entity and the security platforms available. The hunt is created in a draft workspace for review: it never runs before an analyst validates it.
- **Triage**: runs with hits can be sent to the hunt triage agent. Its answer is stored as a **proposed verdict** with a confidence and a rationale; it is never applied automatically, the analyst decides.

## Validation with OpenAEV

When OpenAEV executes an attack simulation for a technique, it asks OpenCTI to run the hunts covering that technique on the security platform of the targeted asset, over the execution window. When those runs complete, the detection result is written on the security coverage of the simulation as the `hunt_detected` coverage, next to the coverages computed by OpenAEV. See [Security coverage](security-coverage.md).

The **Coverage** tab of a hunt gives the status of each of its techniques over every emulation run of the hunt: **Detection proven** once a completed emulation run found hits, **Not detected** when the completed ones found nothing, **Validation in progress** while one is running, **Not validated** before the first one. It also lists the latest emulation runs.

## Hunt packs

Hunts can be shared as **hunt packs**: STIX 2.1 bundles carrying the hunts through a dedicated extension, together with their techniques and targets. Export one or several hunts from the hunts list, import a pack from the same list or deploy it from the XTM Hub. Selecting all the hunts of the list exports every hunt matching its filters and search, not only the loaded page; a pack holds at most 200 hunts, so a larger selection is refused until it is narrowed.

Importing a pack creates the missing hunts and updates the existing ones. The local run settings of an existing hunt (status, schedule, scope, trigger filters, PIR activation) are kept: a pack update changes the logic, never how and where your hunts run. Hunts of a pack that are new to the platform are created as drafts.

## Automation

Hunts can run on a schedule, react to new knowledge, be armed by Priority Intelligence Requirements and be orchestrated by playbooks. See [Hunt automation](hunt-automation.md).

## Access rights

| Action | Capability |
|---|---|
| View hunts and runs | Access knowledge |
| Create, update, run hunts, set verdicts, import packs | Create / Update knowledge |
| Delete hunts | Delete knowledge |
| Register a hunt connector, report runs | Connector API usage |

A hunt run reveals both its hunt and the security platform it ran on. It therefore carries the markings of both, and it is shared only with the organizations both are shared with; a hunt and a platform restricted to different organizations never run together. A run started by a user (a manual run, a translation preview or a retry) only targets the security platforms that user can read, so a platform hidden from the user is never queried on their behalf. Scheduled, standing, playbook and OpenAEV runs target every security platform of the hunt scope.

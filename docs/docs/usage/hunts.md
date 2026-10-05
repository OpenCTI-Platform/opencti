# Hunts

Hunts turn threat intelligence into searches executed in your own telemetry. A hunt states a hypothesis ("if this intrusion set is active in our environment, encoded PowerShell commands run on our endpoints"), carries the detection logic that tests it, and is executed by hunt connectors against the security platforms (SIEM, EDR, XDR, data lakes) your organization operates. Every execution is a **hunt run**: it records what was searched, where, over which time window, what was found and the resulting **verdict**.

Hunts live in the **Defense** area of the navigation, under **Hunts**. The list opens on the statistics of the hunts over a period (runs, hits, true positives, autonomous and failed runs, hits over time, runs per platform, verdicts).

![Defense > Hunts: the statistics of the hunts above the list of hunts](assets/hunt-list-populated.png)

## Concepts

| Concept | Description |
|---|---|
| Hunt | The hypothesis and its logic: a [Sigma](https://sigmahq.io/) rule and, optionally, native queries per platform. A hunt is linked to the techniques (Attack Patterns) it covers, to the threats it targets (Intrusion Sets, Malware, Campaigns, Threat Actors) and to its sources (Indicators, Reports). |
| Hunt run | One execution of a hunt by one hunt connector against one security platform over a time window. |
| Hunt connector | A connector of type `INTERNAL_HUNT` executing hunts on one platform (Splunk, Microsoft Sentinel, Elastic Security, CrowdStrike Falcon LogScale, Google SecOps, OpenSearch, Internet infrastructure tracking). See [Hunt connectors](hunt-connectors.md). |
| Verdict | The conclusion of a run: `pending`, `true_positive`, `benign` or `inconclusive`. |

New to hunting? [Your first hunt](your-first-hunt.md) walks through an indicator hunt, then a hunt with a Sigma rule, in a few minutes.

### Hunt types

The type is the first choice of the creation form: each type says, in one sentence, what it needs as input and where it runs. Pick it from what you have.

![The hunt type of the creation form: each type with what it needs and where it runs](assets/hunt-this-types.png)

| Type | Needs | Runs on |
|---|---|---|
| **Indicators** | Indicators or observables: IP addresses, domains, host names, URLs, email addresses, MAC addresses, file hashes. No query language. | The telemetry of your security platforms, through the hunt connectors that look up indicators. |
| **Detection rule (Sigma or native query)** | A Sigma rule, or a native query per platform (SPL, KQL, EQL, ES\|QL...). | The logs and events of your SIEM, EDR or data lake; hunt connectors translate the Sigma rule into the language of their platform, a native query runs verbatim. |
| **Internet infrastructure (outside-in)** | An internet fingerprint query (certificate, JARM, HTTP title, body hash, `Server` header), not a Sigma rule nor indicators. | Internet scan data (Censys, Silent Push, urlscan.io, Team Cymru Scout), through the infrastructure tracker connector. It never searches your telemetry: it looks for the servers of a threat on the internet. |

- **Indicators** hunts take their values from a list, from reports, groupings, incident responses, threats, tools or incidents, from a filter, or from text pasted in the form. See [Indicator hunts](hunt-indicators.md).
- **Detection rule** hunts carry one Sigma rule and, optionally, native queries that override its translation on their platform.
- **Internet infrastructure** hunts carry a native query of the `internet` platform. The infrastructure tracker connector is described in [Hunt connectors](hunt-connectors.md#infrastructure-tracker).

### Hunt statuses

The status header of a hunt, at the top of every tab of its page, shows the status with its meaning, and **How statuses work** lists the four statuses:

| Status | Meaning |
|---|---|
| Draft | The hunt is being written; it never runs. Hunts proposed by an agent or imported from a hunt pack start as drafts. |
| Active | The hunt runs: on its schedule, when a PIR flags one of its targets, or when you click Run now. |
| Paused | The schedule and the triggers are stopped; Run now still works. |
| Retired | Kept for the record; it never runs again until it is reopened as a draft. |

## Activate a hunt

Next to the status, the header always shows the primary action of the status: **Activate** for a draft, **Pause** for an active hunt, **Resume** for a paused one, **Reopen as draft** for a retired one, with **Run now**, **Preview the query** and **Retire**. Below them, the checklist **Ready to run** lists what the hunt needs, item by item:

| Item | Ready | To complete (what to do) |
|---|---|---|
| Logic | "Valid Sigma rule", "Native query for Splunk", "12 values to look for" | "Add a Sigma rule or a native query", "Invalid Sigma rule: ...", "Add a native query for the internet platform", "Add the indicators or observables to look for" (**Open the logic**) |
| Hunt connector | "Splunk hunt can run it" | "No hunt connector can run it on the platforms of its scope: deploy a hunt connector or widen the scope", "No hunt connector of its scope supports indicator lookups: deploy one that does, such as the Splunk hunt connector" (**Open the hunt connectors**, **How to deploy a hunt connector**) |
| How it runs | "Manual: it runs when you click Run now", "Runs on its schedule: every day at 06:00", "Standing: it runs when a change matches its trigger filters" | "Scheduled, standing and PIR-activated hunts need the Enterprise Edition: set the schedule to manual" (**Edit the schedule**) |
| Scope | "Runs on Splunk Enterprise - SOC", "Runs on every hunt-capable security platform" | "The scope matches no security platform: edit the scope" (**Edit the scope**) |

Some items are warnings: they do not block the activation but deserve a look, for example "Splunk hunt has not answered recently: runs wait in the queue until it is back", or the indicators left out because they are more restricted than the hunt. In a draft workspace, the checklist reminds that the hunt runs once the draft is validated.

![The status header of a draft hunt: the statuses explained, Activate with "1 item to complete" and the checklist naming the missing logic](assets/first-hunt-activation-blocked.png)

**Activate** stays visible while an item is missing: it is disabled and says how many items remain next to it ("1 item to complete"). The platform checks the same items when a hunt becomes active and refuses the activation with the same sentence ("This hunt cannot be activated: Add a Sigma rule or a native query"), whatever the way the hunt is activated (the page, the API, an integration).

## Create a hunt

When the platform holds no hunt yet, **Defense > Hunts** explains what a hunt does, lists what the platform needs before a hunt can run, and offers three starting points, each a short guided flow:

- **Hunt for indicators**: paste values or pick indicators, choose where and how far back, and the hunt starts with its first run;
- **Hunt with a detection rule (Sigma)**: paste a Sigma rule, validated as you type, then the same two steps;
- **Plan a hunt with AI or import a hunt pack**: the AI planner (Enterprise Edition, XTM One) or a hunt pack file or the XTM Hub.

The checklist **Before your first hunt** shows the live state of each prerequisite with its next action: the hunt connectors (none deployed, deployed but not answering, or active and how many look up indicators), XTM One (needed to plan a hunt with AI) and the Enterprise Edition (needed for scheduled and standing hunts and AI planning; manual hunts work without it). It stays above the list of hunts until every prerequisite is met.

![First use of Defense > Hunts: the checklist before the first hunt and the three starting points](assets/hunt-list-first-use.png)

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

Each field says what it is, gives an example and what happens when it is left empty, with a **Learn more** link to the matching section of this page.

![The hunt creation form: every field with its help and Learn more](assets/hunt-form-help.png)

The **Logic** tab keeps the Sigma rule and the native queries of the hunt, validated as you type.

![Logic tab of a hunt: the Sigma rule validated, with its level, log source and detection fields](assets/hunt-logic-sigma-validation.png)

### Hunt this: start a hunt from a threat, a report or an indicator

**Hunt this** is offered on Intrusion Sets, Threat Actors, Campaigns, Malware, Attack Patterns, Reports, Groupings, Incident Responses, Incidents, Indicators, the observables an indicator hunt can look up, and Priority Intelligence Requirements. **Create a hunt** does not open an empty form: the platform first derives what to hunt from the knowledge it holds, with your access (what you cannot see is never derived), and opens the form with it.

| Started from | What the platform derives | The hunt it opens |
|---|---|---|
| Intrusion Set, Threat Actor, Campaign | The indicators and observables of the threat, of the malware and tools it uses, and of the intrusion sets and campaigns attributed to it; the detection rules indicating the techniques it uses. | An indicator hunt over the threat and those sources when indicators exist, otherwise a detection-rule hunt running the rule covering the most techniques. |
| Malware | Its indicators and observables; the detection rules of the techniques it uses. | The same choice. |
| Attack Pattern | The detection rules indicating it. | A detection-rule hunt running one of them. |
| Report, Grouping, Incident Response | The indicators, observables, threats and techniques it contains, and the detection rules of those techniques. | An indicator hunt over the container, otherwise a detection-rule hunt. |
| Incident | The indicators indicating it, the observables related to it, the techniques it uses. | The same choice. |
| Indicator | Its pattern type picks the hunt: a STIX pattern is looked up as an indicator, a Sigma pattern becomes the detection rule, an SPL, KQL, EQL or ES\|QL pattern a native query of its platform. The indicator stays visible and removable. | The hunt its pattern calls for, with the techniques it indicates. |
| Observable | The observable itself. | An indicator hunt looking it up. |

A detection rule is an indicator whose pattern is a Sigma rule or a native query (`sigma`, `spl`, `kql`, `eql`, `esql`) and which indicates a technique, as the defense matrix links detection rules to techniques. Indicators in other pattern languages (YARA, Snort, Suricata) are counted but cannot be hunted.

At the top of the form, two blocks explain the hunt before anything is filled in:

- **The summary** says in plain language what the hunt does, updated as you change the type, the scope, the time window or the escalation threshold: "You are hunting APT28 on 2 security platforms: the hunt searches your telemetry for its 23 known indicators over the last 7 days. A hit creates a sighting and, from 10 hits, proposes an incident."
- **What the platform found** lists the indicators to look up with their count and types ("23 indicators to look up: 12 domains, 8 IPv4 addresses, 3 files"), per source: the threat, each malware or tool it uses and each threat attributed to it can be unticked, and the counts follow. Below, the detection rules of its techniques are proposed as a list, each with the techniques it covers: picking one turns the hunt into a detection-rule hunt running it; **Hunt these indicators** turns it back. When the platform holds neither indicators nor detection rules, the block says so in one sentence and offers **Plan the hunt with AI** and **Import a hunt pack**.

![Hunt this on an intrusion set: the summary, then the 23 indicators of the threat, its malware and the campaign attributed to it, and the detection rules of its techniques](assets/hunt-this-threat.png)

![A detection rule picked from the techniques of the threat: the summary now says which rule runs](assets/hunt-this-rule.png)

![Hunt this on a threat the platform knows nothing about: Plan the hunt with AI or Import a hunt pack](assets/hunt-this-empty.png)

An indicator hunt started this way keeps the threat and its sources as what it looks for: the indicators are read again at every run, so the hunt follows the intelligence as it grows.

## Run a hunt

- **Run now** executes the hunt on every security platform of its scope, each through the hunt connector registered for it. Each platform gets its own run. When no hunt connector serves the scope, the run dialog says so and links to the hunt connectors. A draft or retired hunt cannot run: the button says "Only active or paused hunts can run: activate the hunt from its status".
- **Preview the query**, in the status header and in the **Logic** tab, asks one hunt connector to translate the logic without executing it and displays the query it would run (for an indicator hunt, the lookups of every batch of values). Use it to review what will be executed on a platform before the first run.

![Translation preview in the Logic tab: the SPL query a Splunk hunt connector would execute](assets/hunt-logic-translation-preview.png)

Runs follow the statuses `queued`, `running`, then `completed`, `failed` or `timeout`. A run waits in the queue while its connector is unavailable or busy (each connector has a concurrency and a daily budget). Failed and timed out runs are retried automatically with an exponential backoff. Retrying a terminated run by hand starts its next attempt at once and replaces the automatic retry planned for it, so a run is never retried twice: retrying a run that already has its next attempt opens that attempt.

Runs are visible in the **Runs** tab of the hunt and in the **Hunt runs** list. The work of each run is also listed in the connector works.

## Results, evidence and verdicts

When a run completes, the hunt connector sends to OpenCTI:

- the number of **hits** and of distinct entities,
- an **evidence sample**: the result fields with their occurrence count. Raw values are never stored: each value is hashed and only a truncated preview is kept, in which OpenCTI masks credentials (named fields, authorization headers, the password of a URL such as `https://user:password@host`, command-line arguments such as `curl -u user:password` or `--password value`), tokens, keys, e-mail users and long numbers before storing it, whatever the connector sent,
- **knowledge**: a sighting of each technique and indicator of the hunt, where sighted on the security platform, and observed data referencing the observables extracted from the results (limited to the expected observable types). This knowledge carries the hunt run identifier, so it can always be traced back to the run that produced it.

The page of a run lists the objects it created that you can read, 25 at a time: the list shows how many there are in total, and **Show more** loads the next ones.

Evidence can also be attached to a run later (an alert raised by the SIEM, a follow-up search): it is merged into the run. When it brings hits to a completed run whose verdict was set automatically, the run is finalized again with its new hit count: a run without hits that was `benign` becomes `pending` for triage, an Incident draft is opened at the escalation threshold, and the hunt statistics and the emulation coverage follow. A verdict set by an analyst or an agent is kept; only the statistics and the coverage follow.

The **Evidence** tab of a hunt aggregates the evidence samples of its completed runs: one row per field and hashed value, with its total count, the runs and platforms that saw it and when it was first and last seen. It covers the 100 most recent completed runs; when the hunt has more, the run selector reads "Latest 100 of N runs" and the tab names the date its window starts. The evidence of an older run stays on the page of that run, in the **Runs** tab.

Run statuses and verdicts read the same everywhere (run drawer, lists, widgets), with a colour that says how urgent they are. Red is kept for a true positive, the only state that calls for a response:

| Label | Meaning | Colour |
|---|---|---|
| Queued | Waiting for its hunt connector | Neutral |
| Running | The connector is executing the query | Blue |
| Completed | The query ran; the hits are recorded | Green |
| Failed | The connector reported an error | Orange |
| Timed out | The run passed its deadline | Orange |
| Pending | Hits found, no verdict yet | Neutral |
| Benign | No threat behind the hits | Green |
| Inconclusive | The run cannot decide | Yellow |
| True positive | A threat was found | Red |

![Runs tab of a hunt: one run per verdict, each with the colour of its verdict](assets/hunt-runs-verdicts.png)

The run drawer opens with a status header: the status and verdict, one sentence that says where the run stands (for example "12 hits on 3 entities in Splunk prod - verdict pending") and the next action ("Set the verdict", "Retry" or "Open the incident draft"). A failed run explains why instead of showing the raw error: the connector timed out, the platform refused the query, or the Sigma rule could not be translated, each with its own next action (retry, check the connector, edit the rule); the message reported by the connector stays available under "Show details".

![A completed run: status header, verdict, AI triage proposal with its confidence and rationale, then the evidence](assets/hunt-run-completed-triage.png)

![A failed run: the platform refused the query, with Retry and Check the connector as next actions](assets/hunt-run-failed.png)

The verdict is set as follows:

| Situation | Verdict |
|---|---|
| The run completed with no hit, and its hunt connector stated that the platform returned complete results | `benign`, set automatically |
| The run completed with no hit, but the platform returned partial results (shard failures, a partial answer, an exhausted result budget) | `inconclusive`: no hit in partial results proves nothing. The run shows "partial results" and its hit count reads "At least N" |
| The run completed with no hit, and its hunt connector did not state whether the results are complete | `inconclusive`: no hit proves nothing when the results may be partial. The hunt connectors built on the connectors SDK always state it |
| The run completed with hits | `pending`, until an analyst sets the verdict |
| The run failed or timed out | `inconclusive` |

A run with partial results says why under its status: the platform returned the first N results of the run when the run reached the result limit of its hunt (**Maximum results per run**, 1,000 by default), or partial results otherwise (a failed shard, a partial answer). A run that sends more result objects than a run keeps (as many as the `hunt_manager:max_results_per_run` limit of the platform, 10,000 by default, and never fewer than 5,000) also has partial results, since its results and the playbooks it triggers miss objects. **Narrow the hunt** opens the edition of the hunt, to narrow its time window or its scope so that its next runs fit in what the platform returns. In the **Runs** tab, the hit count of such a run reads "At least N", with the same explanation on hover.

![A run with partial results: the hit count reads "At least 7" and the run explains why, with the next step](assets/hunt-run-partial-results.png)

When the hits reach the escalation threshold, OpenCTI creates an **Incident** in a new draft workspace, never directly in the knowledge graph. The Incident carries the markings and organizations of the run, the workspace is restricted to the organizations the run is shared with, and its name only identifies the run. The Incident description recommends running Case Autopilot once the draft is validated, to investigate the hits and their attribution. Validating the draft makes the Incident part of the knowledge.

Analysts set the final verdict from the run, with an optional feedback. Hunt statistics (runs, hits, verdict distribution, runs per platform) are displayed on the hunt overview and are available as dashboard widgets.

![Overview of a hunt: hypothesis, status and its transitions, schedule, scope and the latest runs](assets/hunt-overview.png)

## AI assistance

!!! tip "Enterprise edition"

    AI assistance for hunts is available under the **OpenCTI Enterprise Edition** licence and requires XTM One. Please read the [dedicated page](../administration/enterprise.md) for full details.

- **Plan a hunt**: from the **Ask AI** menu of a threat, a report or an indicator, the hunt planner agent of XTM One designs a hunt (hypothesis, Sigma rule, native queries, benign patterns, threshold) from the knowledge about the entity and the security platforms available. The hunt is created in a draft workspace for review, with the status **Draft**: validating the workspace creates it, and it runs only once an analyst activates it. When the hunt is planned from restricted intelligence (markings or organizations), the workspace gets a neutral name and description, so the name and hypothesis of the hunt are only shown to the users who can read it. The hunt carries the markings of the intelligence it references and is shared only with the organizations that intelligence all shares; the workspace is then restricted to those organizations and to the user who asked for the hunt. Planning is refused when the intelligence shares no organization, or when the user cannot restrict access to organizations. Through the API (`huntPlan` with `security_platform_ids`), a hunt can be planned for specific security platforms: the planner writes for those platforms only, the proposed hunt is scoped to them, and planning is refused when one of them cannot be found.
- **Triage**: runs with hits can be sent to the hunt triage agent, with whether the platform returned partial results (the hit count is then a lower bound). Its answer is stored as a **proposed verdict** with a confidence from 0 to 100 (shown as "Confidence not assessed" when the agent cannot weigh the evidence, never replaced by a number) and a rationale; it is never applied automatically, the analyst decides. Accepting the proposal records the verdict as the agent's; any other verdict, whether set from the run, through the API or by an XTM One agent on request, is recorded as the decision of the analyst who sets it.

A hunt proposed by an agent, or imported from XTM Hub, opens with a banner listing what remains before it can run: review the hypothesis and the logic, add the logic it lacks, switch an autonomous schedule to manual without the Enterprise Edition, validate the draft workspace. Once the hunt has its logic and can run outside a draft workspace, the banner offers **Activate the hunt**.

![Draft banner of a hunt proposed by an agent: what remains before it runs](assets/hunt-draft-banner.png)

Both answers are checked by XTM One against the hunt contract before they are returned, and again by OpenCTI. When an agent cannot produce an answer that passes its own check, OpenCTI reports the reasons the agent listed instead of an answer.

## Validation with OpenAEV

When OpenAEV executes an attack simulation for a technique, it asks OpenCTI to run the hunts covering that technique on the security platform of the targeted asset, over the execution window. When those runs complete, the detection result is written on the security coverage of the simulation as the `hunt_detected` coverage, next to the coverages computed by OpenAEV. A request naming a security coverage OpenCTI cannot find is refused, so OpenAEV records the failure rather than a validation whose result no coverage receives. See [Security coverage](security-coverage.md).

The **Coverage** tab of a hunt gives the status of each of its techniques over every emulation run of the hunt: **Detection proven** once a completed emulation run found hits, **Not detected** when the completed ones found nothing, **Validation in progress** while one is running, **Not validated** before the first one. It also lists the latest emulation runs.

## Hunt packs

Hunts can be shared as **hunt packs**: STIX 2.1 bundles carrying the hunts through a dedicated extension, together with their techniques and targets. Export one or several hunts from the hunts list, import a pack from the same list or deploy it from the XTM Hub. Selecting all the hunts of the list exports every hunt matching its filters and search, not only the loaded page; a pack holds at most 200 hunts, so a larger selection is refused until it is narrowed.

Importing a pack creates the missing hunts and updates the existing ones. A hunt is identified by its name: a pack hunt with the name of a hunt of the platform updates that hunt, whatever STIX ID the pack gives it. The local run settings of an existing hunt (status, schedule, scope, trigger filters, PIR activation) are kept: a pack update changes the logic, never how and where your hunts run. Hunts of a pack that are new to the platform are created as drafts. Every hunt of the pack is checked before the first one is written, and the pack is refused as a whole, with nothing imported, when it holds an invalid hunt, two hunts with the same name, or a hunt named like a hunt of the platform you cannot read.

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

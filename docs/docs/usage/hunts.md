# Hunts

Hunts turn threat intelligence into searches executed in your own telemetry. A hunt states a hypothesis ("if this intrusion set is active in our environment, encoded PowerShell commands run on our endpoints"), carries the detection logic that tests it, and is executed by hunt connectors against the security platforms (SIEM, EDR, XDR, data lakes) your organization operates. Every execution is a **hunt run**: it records what was searched, where, over which time window, what was found and the resulting **verdict**.

Hunts live in the **Defense** area of the navigation, under **Hunts**. The list opens on the statistics of the hunts over a period (runs, hits, true positives, autonomous and failed runs, hits over time, runs per platform, verdicts). They cover the hunts that exist: the runs of a deleted hunt leave them, and come back when the hunt is restored from the trash.

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

A user who cannot change the hunt (without the knowledge update capability, or with only view access to the draft workspace that holds it) sees the status and the checklist without these actions and without **Edit the schedule** and **Edit the scope**.

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
- the **Sigma rule**: it is validated while you type, the platform reports the parsing errors, the detection fields and the ATT&CK techniques found in its tags. Techniques found in the tags are linked to the hunt automatically. **Generate with AI**, next to its label, proposes the rule with XTM One (see [Generate with AI](#generate-with-ai)),
- optional **native queries**, one per platform, executed verbatim instead of the translated Sigma rule (**Add a native query**, next to the label),
- the **targets** (threats) and the **sources** (indicators, reports) of the hunt,
- the **time window** searched by each run (24 hours by default),
- the **observables to extract from hits**, under **What a run produces**: the observable types whose values found in the hits become observables (the default types when left empty, see [What a run produces](#what-a-run-produces)); indicator hunts do not use it,
- the **benign patterns**: known legitimate activity, shared with the triage agent,
- the **escalation threshold**: from this number of hits, a completed run proposes an Incident (see below),
- the **scope**: the security platforms the hunt runs on (all the platforms served by a hunt connector when empty).

Each field says what it is, gives an example and what happens when it is left empty, with a **Learn more** link to the matching section of this page; the **Learn more** of the drawer header, next to its close button, opens this section. Fields that need the Enterprise Edition (the autonomous schedules, the PIR activation) carry the **EE** chip right after their label.

![The hunt creation form: every field with its help and Learn more](assets/hunt-form-help.png)

![The header of the hunt creation drawer, with Learn more next to its close button](assets/hunt-drawer-header.png)

![The Sigma rule and the native queries of the creation drawer: Generate with AI and Add a native query in their label row](assets/hunt-drawer-logic.png)

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

The overview of a report, a malware or an indicator then shows a **Hunts** card: the hunts that look for it or use it as a source, each with its status, the verdict of its latest execution (Pending until an analyst gives one, Never run for a hunt not executed yet; query previews do not count) and the date and hits of that execution (the ten most recently run, the others in the hunts list). The card is not shown when no hunt uses the entity.

## Run a hunt

- **Run now** executes the hunt on every security platform of its scope, each through the hunt connector registered for it. Each platform gets its own run. When no hunt connector serves the scope, the run dialog says so and links to the hunt connectors. A draft or retired hunt cannot run: the button says "Only active or paused hunts can run: activate the hunt from its status". When the platform refuses the start, for example because the hunt connector stopped after the dialog opened, the dialog stays open and says why, so that you can fix the cause and run again.

![The run dialog when the hunt could not be started: the hunt connector of the scope stopped](assets/hunt-run-start-error.png)
- **Preview the query**, in the status header and in the **Logic** tab, asks one hunt connector to translate the logic without executing it and displays the query it would run (for an indicator hunt, the lookups of every batch of values). Use it to review what will be executed on a platform before the first run.

![Translation preview in the Logic tab: the SPL query a Splunk hunt connector would execute](assets/hunt-logic-translation-preview.png)

Runs follow the statuses `queued`, `running`, then `completed`, `failed` or `timeout`. A queued or running run whose hunt or hunt connector is deleted ends `cancelled`: it gets no verdict, is never retried and never counts in the statistics. A run waits in the queue while its connector is unavailable or busy (each connector has a concurrency and a daily budget). Failed and timed out runs are retried automatically with an exponential backoff. Retrying a terminated run by hand starts its next attempt at once and replaces the automatic retry planned for it, so a run is never retried twice: retrying a run that already has its next attempt opens that attempt.

Runs are visible in the **Runs** tab of the hunt and in the **Hunt runs** list. The work of each run is also listed in the connector works.

## Results, evidence and verdicts

When a run completes, the hunt connector sends to OpenCTI:

- the number of **hits** and of distinct entities,
- an **evidence sample**: the result fields with their occurrence count. Raw values are never stored: each value is hashed and only a truncated preview is kept, in which OpenCTI masks credentials (named fields, authorization headers, the password of a URL such as `https://user:password@host`, command-line arguments such as `curl -u user:password` or `--password value`), tokens, keys, e-mail users and long numbers before storing it, whatever the connector sent,
- the **key of every hit** it read, which tells OpenCTI the hits it never saw before (see [How hits are counted](#how-hits-are-counted)),
- **knowledge**: the observables and observed data described in [What a run produces](#what-a-run-produces). This knowledge carries the hunt run identifier, so it can always be traced back to the run that produced it.

The page of a run lists the objects it created that you can read, 25 at a time: the list shows how many there are in total, and **Show more** loads the next ones.

### What a run produces

The raw events never leave the hunted platform: OpenCTI receives the hit count, the masked evidence sample and the objects below, each stamped with the run that produced it.

| Created by | What | When |
|---|---|---|
| OpenCTI | One **sighting** of each technique and each indicator of the hunt, sighted by the security platform of the run, kept for the hunt: the first run with hits creates it, every later run updates it in place (count of distinct hits, first and latest hit), see [How hits are counted](#how-hits-are-counted) | Detection-rule hunts, for a run with hits on a security platform |
| The hunt connector | An **observable** for each value of the **observables to extract from hits** found in the matching events, each with an **observed data** counting its occurrences | Detection-rule and internet infrastructure hunts. The hunt connector extracts only the types it supports, up to the maximum number of observables its configuration allows |
| OpenCTI | An **observed data** for each hit of the evidence sample (20 at most, `hunt_manager:hit_observed_data_max_items`), holding the observables the hit names: its host, its account and the values of the fields the hunt logic matched (addresses, URLs, host names, domains, file hashes, command lines) | When a run completes with hits. A value OpenCTI masked or truncated names nothing and is skipped |
| OpenCTI | An **Incident** in a new draft workspace, or the hits of the run added to the incident still open from a previous run | From the escalation threshold of new hits, see below |

Left empty, **Observables to extract from hits** stands for the default types, which the empty field names and the hunt page lists: IPv4 address, IPv6 address, domain name, URL, file, email address, hostname, user account and X509 certificate. A type a hunt connector does not support is ignored on its platform. An indicator hunt does not use this list, so its forms and its page do not show it: OpenCTI keeps one sighting of each indicator or observable its values come from (see [Results and verdicts](hunt-indicators.md#results-and-verdicts)). An internet infrastructure hunt creates no sighting: the hosts it finds become an infrastructure related to the targeted threats, with an observable, an indicator and an observed data for each value of the types to extract, the certificates of the hosts included when the hunt connector is configured to create them.

The run drawer sums this up under **Knowledge produced**, for example "1 sighting created, 2 sightings updated, 5 observed data, 3 observables", counted over the objects you can read. When a completed run with hits produced no observable and no observed data, it says why: the hits carried no value of the types to extract, or the hunt connector does not support these types. When a detection-rule run with hits produced no sighting, it says why too: the run has no security platform, or the hunt names no technique or indicator to sight.

### How hits are counted

A hunt that runs again and again (a schedule, a standing hunt, an activation by a PIR) never counts the same activity twice:

- **Each run searches since the previous one.** A recurring run starts where the previous completed run of the hunt on the same security platform ended, minus an overlap that catches the events the platform indexed late (15 minutes by default, `hunt_manager:schedule_lookback_minutes`), and never searches more than the time window of the hunt. The first run, a run after a long pause, and the first run after the Sigma rule or the native queries of the hunt changed search the whole time window. A run started by hand, a retry, a playbook run and an OpenAEV validation run search the window they are given. The run drawer says "Searched since the previous run on Splunk prod, with a 15-minute overlap" and the schedule field of the hunt form says it before you save.
- **Each hit has an identity.** The hunt connector gives every hit it reads a stable key: the detection of the platform when the platform groups events into detections, else the id of the event on the platform, else a hash of the time of the event (to the second), its host, user and process, and the fields the hunt logic matched. OpenCTI recomputes the key of each sampled hit the same way.
- **Known hits are remembered.** OpenCTI keeps the hits each hunt already found, per security platform, as long as it keeps runs (`hunt_manager:run_retention_days`, one year by default): a hit no run found since is forgotten. Each run then reads "120 hits (12 new, 108 seen before)", each sampled hit of the run drawer is tagged **New** or "Seen 4 times since" a date, the hunt page shows its **Known hits** (distinct hits, when the first was found and the last new one) and the new hits of its last run, and the hunts list shows them next to the hits of the last run. A hunt connector that does not identify its hits (an older one, or a lookup that returns counts instead of events) makes every hit of its runs new, and the run drawer says so.
- **Only new hits escalate.** The escalation threshold applies to the new hits of a run: a hunt that keeps finding the same activity opens nothing new. When a previous run of the hunt on the same platform opened an incident that is still open (its draft is not validated yet, or it was validated and its status is not the last one of the incident workflow), the run adds its hits to that incident instead of opening another one: the incident gets relations to the new observed data and observables and a note with the summary of the run, in its draft while the draft is not validated. A new incident draft is opened only when none is open.
- **One sighting per technique and platform.** OpenCTI keeps a single sighting of each technique and indicator of the hunt on each security platform, created by the first run with hits and updated in place by the next ones: its count holds the distinct hits found so far, its first and last seen dates the first and the latest hit, and it names the hunt and the run that updated it last. Its identity derives from the hunt, the technique or indicator and the platform, so it never merges with the sighting of another hunt or of a connector that has the same dates. Earlier versions created a sighting per run; those stay as they are.

![The hits of a scheduled run in its drawer: 120 hits, 12 new and 108 seen before, searched since the previous run, each sampled hit tagged New or Seen 2 times since its first date](assets/hunt-hits-run-drawer-1440.png)

Evidence can also be attached to a run later (an alert raised by the SIEM, a follow-up search): it is merged into the run. Evidence attached while the run is still running is kept: the report of its hunt connector adds its hits, samples and results to it. When it brings hits to a completed run whose verdict was set automatically, the run is finalized again with its new hit count: a run without hits that was `benign` becomes `pending` for triage, an Incident draft is opened at the escalation threshold, and the hunt statistics and the emulation coverage follow. A verdict set by an analyst or an agent is kept; only the statistics and the coverage follow.

The **Evidence** tab of a hunt aggregates the evidence samples of its completed runs: one row per field and hashed value, with its total count, the runs and platforms that saw it and when it was first and last seen. It covers the 100 most recent completed runs; when the hunt has more, the run selector reads "Latest 100 of N runs" and the tab names the date its window starts. The evidence of an older run stays on the page of that run, in the **Runs** tab.

Run statuses and verdicts read the same everywhere (run drawer, lists, widgets), with a colour that says how urgent they are. Red is kept for a true positive, the only state that calls for a response:

| Label | Meaning | Colour |
|---|---|---|
| Queued | Waiting for its hunt connector | Neutral |
| Running | The connector is executing the query | Blue |
| Completed | The query ran; the hits are recorded | Green |
| Failed | The connector reported an error | Orange |
| Timed out | The run passed its deadline | Orange |
| Cancelled | Its hunt or its hunt connector was deleted | Neutral |
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

When the new hits of a run reach the escalation threshold, OpenCTI creates an **Incident** in a new draft workspace, never directly in the knowledge graph, unless an incident of a previous run of the hunt on the same platform is still open: the hits then go to that incident (see [How hits are counted](#how-hits-are-counted)). The Incident carries the markings and organizations of the run, the workspace is restricted to the organizations the run is shared with, and its name only identifies the run. The Incident description recommends running Case Autopilot once the draft is validated, to investigate the hits and their attribution. Validating the draft makes the Incident part of the knowledge.

Analysts set the final verdict from the run, with an optional feedback. A true positive on a run without an incident offers **Escalate to an incident**, on by default: the hits go to the incident still open from a previous run of the hunt on the platform, or to a new incident draft; turned off, the true positive is recorded alone. Hunt statistics (runs, hits, verdict distribution, runs per platform) are displayed on the hunt overview and are available as dashboard widgets.

![Overview of a hunt: hypothesis, status and its transitions, schedule, scope and the latest runs](assets/hunt-overview.png)

## AI assistance

!!! tip "Enterprise edition"

    AI assistance for hunts is available under the **OpenCTI Enterprise Edition** licence and requires XTM One. Please read the [dedicated page](../administration/enterprise.md) for full details.

- **Plan a hunt**: from the **Ask AI** menu of a threat, a report or an indicator, the hunt planner agent of XTM One designs a hunt (hypothesis, Sigma rule, native queries, benign patterns, threshold) from the knowledge about the entity and the security platforms available. The hunt is created in a draft workspace for review, with the status **Draft**: validating the workspace creates it, and it runs only once an analyst activates it. When the hunt is planned from restricted intelligence (markings or organizations), the workspace gets a neutral name and description, so the name and hypothesis of the hunt are only shown to the users who can read it. The hunt carries the markings of the intelligence it references and is shared only with the organizations that intelligence all shares; the workspace is then restricted to those organizations and to the user who asked for the hunt. Planning is refused when the intelligence shares no organization, or when the user cannot restrict access to organizations. Through the API (`huntPlan` with `security_platform_ids`), a hunt can be planned for specific security platforms: the planner writes for those platforms only, the proposed hunt is scoped to them, and planning is refused when one of them cannot be found.
- **Generate with AI and Plan with AI**: the hunt forms write their fields with the hunt planner of XTM One, see [Generate with AI](#generate-with-ai) below.
- **Triage**: runs with hits can be sent to the hunt triage agent, with whether the platform returned partial results (the hit count is then a lower bound). Its answer is stored as a **proposed verdict** with a confidence from 0 to 100 (shown as "Confidence not assessed" when the agent cannot weigh the evidence, never replaced by a number) and a rationale; it is never applied automatically, the analyst decides. Accepting the proposal records the verdict as the agent's; any other verdict, whether set from the run, through the API or by an XTM One agent on request, is recorded as the decision of the analyst who sets it.

A hunt proposed by an agent, or imported from XTM Hub, opens with a banner listing what remains before it can run: review the hypothesis and the logic, add the logic it lacks, switch an autonomous schedule to manual without the Enterprise Edition, validate the draft workspace. Once the hunt has its logic and can run outside a draft workspace, the banner offers **Activate the hunt**.

![Draft banner of a hunt proposed by an agent: what remains before it runs](assets/hunt-draft-banner.png)

Every answer is checked by XTM One against the hunt contract before it is returned, and again by OpenCTI. When an agent cannot produce an answer that passes its own check, OpenCTI reports the reasons the agent listed instead of an answer.

### Generate with AI

The creation drawer, the edition drawer, the guided Sigma hunt and the **Logic** tab share the same AI help, from the hunt planner of XTM One:

- **Generate with AI on a field**: at the end of the label row of every field the planner can fill - **Hypothesis**, **Description**, **Sigma rule**, each **Native query** once its platform and query language are chosen, **Observables to extract from hits** and **Benign patterns**.
- **Plan with AI**: in the form header, next to the hunt type, the whole plan at once - the name when the hunt has none, the hypothesis, the description, the Sigma rule or the native queries, the observables to extract, benign patterns and techniques.

**What it uses.** The whole form: the name, the hunt type, the targeted threats, the covered techniques, the indicators and reports the hunt is based on, the security platforms with the query languages of their hunt connectors, and every field already filled (a Sigma rule being edited is refined rather than replaced). In the **Logic** tab, the saved hunt completes what the tab does not show. The planner also looks up in the knowledge of the platform what the name or the hypothesis mentions. A name is enough to start; when the form says nothing yet, the dialog first asks **What do you want to hunt?** and the planner starts from your words.

**What it proposes.** While the planner works, the dialog shows what it is doing and the elapsed time, with **Cancel**. Its answer is a proposal: the field you asked for, which you can edit, the reason the planner gives, and under **Also add** what the same answer implies for the empty fields of the form (for example the hypothesis or the name when you asked for the Sigma rule) and the ATT&CK techniques it named that exist on the platform. In a plan, each part has its box; the parts that would replace what you wrote are unchecked until you check them.

**What you accept.** Nothing changes in the form until you click **Accept**: the field you asked for takes the proposal as you left it, and each **Also add** chip you clicked adds its value (observables, benign patterns and techniques are added to the ones already there). **Regenerate** asks again, **Dismiss** leaves the form as it was. Nothing is saved before you create or update the hunt, or save its logic; in the **Logic** tab, **Save and preview** saves the logic and asks a hunt connector for the query it would run.

![Generate with AI on the Sigma rule: the rule to review, and what the same answer implies for the empty fields under Also add](assets/hunt-drawer-ai-proposal.png)

![Plan with AI from an empty form: the dialog first asks what to hunt](assets/hunt-drawer-ai-prompt.png)

![The plan as one proposal: each part has its box, the techniques are added when checked](assets/hunt-drawer-ai-plan.png)

![The Sigma rule once accepted, with the live validation of the platform](assets/hunt-drawer-sigma-generated.png)

**When it is unavailable or fails.** The actions are disabled only when XTM One is not configured on the platform: the drawer header says so once, with **Open the settings** for an administrator or **Ask your administrator** for anyone else, and each field repeats the reason on hover and focus; the **Logic** tab and the guided hunt say it next to the action. A failure names its cause and the next step, with **Retry**: XTM One cannot be reached or did not answer in time, it refused the credentials of the platform, its AI quota is used up, it could not run the agent (most often because no AI model is configured in XTM One, under Settings > AI Models), no agent is bound to the hunt planner intents, or the answer did not pass the checks of the platform.

![The progress of the planner, with Cancel](assets/hunt-drawer-ai-progress.png)

![A failure names its cause and the next step, with Retry](assets/hunt-drawer-ai-error.png)

![The only disabled state: XTM One is not configured, said once in the form header with Open the settings](assets/hunt-drawer-sigma-unavailable.png)

Through the API, `huntAssist` takes the fields to write (none for the whole plan), an optional description of what to hunt and the hunt as it is being written (or the identifier of a saved hunt), and returns the proposal with the validation of its Sigma rule and the techniques found on the platform. It requires the knowledge update capability, saves nothing, and every call is recorded in the activity of the user. A failed call carries its cause in the `failure` field of the error data (`XTM_ONE_NOT_CONFIGURED`, `XTM_ONE_UNREACHABLE`, `XTM_ONE_TIMEOUT`, `XTM_ONE_REFUSED`, `XTM_ONE_QUOTA`, `XTM_ONE_NO_MODEL`, `XTM_ONE_NO_AGENT`, `XTM_ONE_INVALID_ANSWER`, `XTM_ONE_INCOMPLETE`).

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

Running a hunt, retrying, triaging its runs, attaching evidence to them and setting their verdicts change the hunt: in a draft, like an update of the hunt, they take the edit access to the draft. A user who can only view the draft sees the runs of its hunts without their controls. Hunts and their runs cannot be restricted to members: their access follows their markings and organizations.

A hunt run reveals both its hunt and the security platform it ran on. It therefore carries the markings of both, and it is shared only with the organizations both are shared with; a hunt and a platform restricted to different organizations never run together. The sightings, observed data and incidents of a run carry the same markings and organizations, and a sighting updated by a later run takes those of that run. A run started by a user (a manual run, a translation preview or a retry) only targets the security platforms that user can read, so a platform hidden from the user is never queried on their behalf. Scheduled, standing, PIR armed, playbook and OpenAEV runs target every security platform of the hunt scope.

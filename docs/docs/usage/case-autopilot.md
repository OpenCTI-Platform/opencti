# Case Autopilot

!!! tip "Enterprise edition"

    Case Autopilot is available under the "OpenCTI Enterprise Edition" license. Please read the [dedicated page](../administration/enterprise.md) for full details.

Case Autopilot investigates an incident, a case, an indicator or an observable for you. It reads what the case holds, checks what OpenCTI already knows, enriches through the enrichment connectors of your platform, weighs the competing hypotheses and writes a cited report. Everything it writes goes to a [draft](draftWorkspaces.md) that an analyst reviews and approves: nothing reaches your knowledge graph without that approval, unless the investigation policy allows it for low-risk objects.

Case Autopilot is the OpenCTI face of the XTM One investigation engine (Deep Investigation). OpenCTI keeps the investigation run, its policy, its budget, its draft, its approvals and every write; XTM One plans the investigation and queries its sources. XTM One never calls a vendor directly: every enrichment goes through the OpenCTI connectors, so markings, quotas and connector settings apply.

## Requirements

- An Enterprise Edition license.
- XTM One connected to the platform (see the [XTM Suite configuration](../deployment/configuration.md#xtm-suite)), in a version that provides the investigation engine. When XTM One is not connected or does not run investigations, the Autopilot tab says so and no investigation starts.
- To start an investigation: the capabilities to update knowledge and to enrich knowledge.
- To manage investigation policies: the capability to manage customization.

## Run Case Autopilot

Open the **Ask AI** menu in the header of an incident, a case (incident response, request for information, request for takedown), an indicator or an observable, and choose **Run Case Autopilot**.

In the dialog:

- pick the **investigation policy** (the default policy is preselected);
- for an indicator or an observable, choose the **case of the investigation**: an existing case (the cases that contain the entity are listed first), or a new incident response case created in the investigation draft. The results of an investigation always live in the Autopilot tab of a case;
- choose whether the investigation graph opens when the investigation completes.

The dialog also lists the previous investigations of the entity.

The overview of an indicator or an observable shows a compact **Latest investigation** link with the status of its latest investigation; it opens the Autopilot tab of the case of that investigation.

## The Autopilot tab

Incidents and cases have an **Autopilot** tab, after the Content tab. When several investigations exist, a selector switches between them; the latest one is open and updates live. The tab shows, in this order:

1. **Header**: the pack of the investigation engine, the status and phase of the run, the use of the budget (iterations, enrichment jobs, minutes), the link to the investigation draft and the **Approve** action, and **Continue investigation** when the engine can go further.
2. **Goal plan**: the objective of the investigation and its actions, each with the steps that served it. Every step has one of seven states: Planned step, Querying, Found, Nothing found, Partial, Failed, Not reached. Only a step that found something is a success.
3. **Evidence**: what the investigation cited - web pages, documents, tool results and OpenCTI objects - with the citation numbers of the report. OpenCTI objects that are still in the draft are marked as such.
4. **Hypotheses**: an Analysis of Competing Hypotheses (ACH) matrix. The engine proposes the candidates and links the evidence; OpenCTI scores them deterministically: each evidence weighs by its category (infrastructure overlap, tooling, TTP overlap, victimology, temporal plausibility, source reliability, language and time zone), its reliability and how well it tells the hypotheses apart. Each hypothesis gets a probability (an implicit "unknown actor" keeps part of it) and a confidence on a fixed estimative scale, from Remote to Almost certain. A hypothesis that no evidence assessed shows **Not assessed**: its confidence is never invented. Accept or reject each hypothesis to give feedback.
5. **Recommendations**: the courses of action and tasks the investigation proposes, with their priority. Create a task or apply a course of action in one click; recommendations that change the severity, share, notify or close the case wait for an approval. Accept or reject each recommendation to give feedback.
6. **Report**: the cited report of the investigation and its numbered sources. The report is also written to the draft as a Report, its sources as external references.

## Approvals

An investigation pauses and waits for an analyst when:

- an enrichment goes through a connector that the policy marks as needing an approval (paid or rate-limited services);
- a recommendation would change the severity of the incident, share knowledge, send a notification or close the case;
- the investigation draft is ready for review.

Pending approvals appear at the top of the Autopilot tab. Once an analyst approved an enrichment the investigation held, **Continue investigation** starts a new engine run on the same investigation, with the new knowledge.

## Investigation policies

Investigation policies are managed in **Settings > Customization > Investigation policies**. A policy defines:

| Setting | Description |
|:--|:--|
| Investigation pack | The pack of the XTM One investigation engine. The picker lists the packs the connected XTM One offers, with the options of the selected pack. The default is the built-in "OpenCTI case investigation" pack. |
| Pinned agent | Optional XTM One agent; by default, the agent bound to the autonomous investigation intent. |
| Actions allowed without asking | What the investigation may do without an approval: run enrichment connectors, create a case, add evidence to the case, write the summary note, write the attribution relationship. |
| Enrichment connectors | The connectors the investigation may use (all when empty). |
| Connectors that need an approval | Connectors whose every enrichment waits for an analyst approval. |
| Low-risk automatic approval | Approve the draft automatically when it holds only notes and observed data and the leading hypothesis reaches the minimum confidence. |
| Minimum confidence to write an attribution | The attribution relationship is written to the draft only above this confidence. |
| Budget | Maximum iterations of the engine, maximum enrichment jobs and maximum duration. OpenCTI enforces the budget and cancels the engine run when the duration is exceeded. |
| Investigate every new request for information | Start an investigation automatically when a request for information is created. |
| Run automatic investigations as | The user automatic investigations act as. |

The policy page also shows, per policy, the number of investigations and the share of hypotheses and recommendations analysts accepted.

One policy is the default: it cannot be deleted, and promoting another policy to default replaces it. A policy used by investigations in progress cannot be deleted until they end; the investigations it already ran are kept. When the creation of an automatic investigation fails for a technical reason (for example the database is briefly unavailable), the request for information is investigated on the next attempt rather than skipped.

## Automate with playbooks

The playbook component **Run Case Autopilot** starts an investigation for each incident or case of the bundle, once per entity, with the policy you select. Combine it with a playbook listening to the incidents your incident connectors create (for example Microsoft Sentinel incidents, Microsoft Defender incidents or CrowdStrike) to investigate every new incident as it arrives. See [playbook components](playbook-components.md).

## Notifications

Live triggers and digests can listen to three investigation events, delivered on the case of the investigation: **Investigation awaiting approval**, **Investigation completed** and **Investigation failed**. Assignees and participants of a case receive them without any setup. See [notifications and alerting](notifications.md).

## Feedback and report template

Every accept or reject decision is stored on the investigation and sent to XTM One, which calibrates its later investigations. The built-in fintel template **Autonomous investigation summary** (Settings > Customization > Fintel design) generates a document from the investigation: executive summary, timeline, hypotheses, recommendations and indicators.

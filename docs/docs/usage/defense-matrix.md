# Defense matrix

The defense matrix answers three questions for every MITRE ATT&CK technique, on every security platform you operate: can you **see** it, can you **detect** it, and did you **prove** it? It compares the answer with the techniques used by the threats you care about, and turns the difference into a prioritized backlog.

The matrix is computed by OpenCTI from knowledge you already have. It is deterministic: every level is explained by the evidences that produced it, and nothing is deployed automatically.

The defense matrix is available in the Community Edition, under **Defense > Defense matrix**. It is also reachable from **Techniques > Attack patterns** with the **Open in Defense matrix** button.

## Defense levels

Each technique gets one level per security platform, and one aggregated level over all platforms.

| Level | Name | Evidence |
|:------|:-----|:---------|
| 0 | None | Nothing is known about this technique. |
| 1 | Telemetry | A security platform `provides` a data component that `detects` the technique. |
| 2 | Detection available | A detection rule (an Indicator with a rule pattern type such as Sigma, YARA, Snort, Suricata, SPL, EQL, KQL or YARA-L) `indicates` the technique. Its deployment is unknown. |
| 3 | Detection deployed | The rule is `deployed-on` the security platform, with a deployed or active status. |
| 4 | Validated | OpenAEV proved the detection or the prevention of the technique on the platform. |

A failed latest validation caps the level at 2: the detection is deployed, but it was proven ineffective. A technique is considered **covered** from level 3.

Mitigations (courses of action that `mitigate` the technique) are shown as a separate marker: they do not change the level.

!!! note "Access to evidences"

    Levels are recomputed for each reader from the evidences this reader can access (markings and organizations). A rule, a data component or a validation result you cannot see never contributes to the levels displayed to you, in the matrix, the backlog, the widgets and the notifications alike. The levels are therefore not attributes of the attack patterns: they cannot be used in the filters of lists or knowledge widgets. A change of your groups, organizations or markings applies to the next page you load.

Revoked techniques leave the matrix: their stored levels and gaps are removed at the next computation, and come back if the technique is no longer revoked.

## Declare the telemetry of a security platform

A security platform, or a system, declares the MITRE data components it collects with the `provides` relationship.

* On a **Security platform**, open the **Coverage** tab. The **Provided telemetry** card lists the data components and lets you add one with the relationship creation, or declare log sources: describe them with the Sigma taxonomy (category, product, service) and OpenCTI turns them into data components through the telemetry mappings.
* On a **System**, create the `provides` relationship to a data component from the knowledge view, like any other relationship.

Telemetry is also inferred from the log sources of the rules running on a platform (deployment status deployed or active): a pending, failed, removed or expired deployment does not prove that the platform collects the log source.

### Telemetry mappings

The mapping from Sigma log sources to MITRE data components is managed in **Settings > Customization > Telemetry mappings**. OpenCTI ships built-in mappings, which you can edit or deactivate, and you can create your own mappings. **Restore built-in mappings** gives the built-in entries back their shipped data components and reactivates them; custom mappings are kept.

## Detection rules

Detection rules are Indicators whose pattern type is a rule language. The rule metadata is stored on the Indicator and normalized (trimmed, lower case): status, level and log source (category, product, service).

Connectors import public rule repositories (SigmaHQ, Valhalla, ...) and the rules deployed in your SIEM and EDR (Splunk saved searches, Elastic, Microsoft Sentinel, CrowdStrike custom IOA rules, Google SecOps YARA-L rules). Rules deployed on a platform are linked to it with the `deployed-on` relationship and its deployment status.

## Matrix tab

The **Matrix** tab displays the ATT&CK matrix with the defense level of each technique.

* **Security platforms**: select one or several platforms to restrict the levels, or keep all of them.
* **Threats**: choose the threats to compare with: all threats, selected threats, threats matching a filter, or none. Techniques used by these threats are outlined, with the number of threats using them.
* **Layers**: show or hide telemetry, detection, validation and mitigations.
* The coverage summary and the coverage by tactic give the share of techniques at each level, over all techniques and over the techniques used by the selected threats.

The selected platforms and threats are remembered per user, in the browser, and shared by the Matrix and Gaps tabs. Every level and every threat count only uses the knowledge you can access: a change of the `uses` relationships or of the markings and organizations of a threat is reflected at the next refresh.

Click a technique to open its drawer. It explains the level per platform: the data components and the platforms providing them, the detection rules and their deployments, the OpenAEV results behind the displayed level (those of the selected platforms), the mitigations, the threats using the technique and the validation requests already sent.

The coverage is computed in the background by the defense coverage manager: a full computation every night and an incremental computation when the knowledge changes. Users allowed to customize the platform can request a full computation with **Recompute**.

## Gaps tab

The **Gaps** tab lists every technique and platform pair below level 4, with:

* its level and the **recommended action**: add telemetry, import a rule, deploy a rule, activate a rule, validate, or fix the detection after a failed validation;
* its **priority**, based on the threats using the technique (weighted by the confidence of their relationships) and on its level;
* the **rule candidates**: rules indicating the technique that are not deployed yet, ranked by the compatibility of their log source with the telemetry of the platform.

The backlog shares the scope of the matrix (platforms and threats). It can be filtered (levels, recommended actions, techniques used by the threats only, search), sorted, and exported to CSV.

## Validate in OpenAEV

Select gaps in the Gaps tab, or open a gap drawer, and click **Validate in OpenAEV**. OpenCTI creates a grouping holding the selected techniques (and the threat to emulate, if any) and a [security coverage](security-coverage.md) of this grouping, so that OpenAEV generates a scenario restricted to these techniques. The request is tracked on the gaps.

When OpenAEV sends the results back, they update the validation layer. OpenAEV attributes each result to the security platform that produced it, so a validation is applied to the right platform.

Applications requesting a validation through the API (`defenseGapsValidate` mutation) can pass an `external_reference_url`, an http or https link to what asked for the validation (a risk scenario, a ticket). It is stored as an external reference of the security coverage, named after the host of the link.

## Notifications

A [live trigger](notifications.md#triggers) can listen to two defense events in addition to creation, modification and deletion:

| Event | Sent when |
|:------|:----------|
| **Defense level decreased** | The aggregated defense level of a technique, as the recipient sees it, goes down: for example a rule is removed from a platform, a platform stops providing a data component or the latest OpenAEV validation failed. |
| **Defense level increased** | The aggregated defense level of a technique, as the recipient sees it, goes up: for example a rule is deployed or a validation succeeds. |

The notification names the technique and both levels, for example "defense level decreased from 3 (detection deployed) to 1 (telemetry)". Use the trigger filters to restrict it, for example to attack patterns with a given kill chain phase or label.

Each recipient is told about the level they see: both levels are computed from the evidences the recipient can access, so a change caused only by a rule, a relationship or a result they cannot see sends them nothing, and a change they can see is reported even when other evidences keep the overall level unchanged. An evidence deleted since the previous computation counts with the markings and organizations it had, as kept in the [trash](delete-restore.md#trash); once it is no longer in the trash, it no longer counts for anyone but the users who bypass access restrictions. A recipient is only notified about techniques they can access. The first computation of the matrix sets the levels without notifying, and a recomputation that leaves a level unchanged notifies nobody. Digests built on these triggers collect the events like any other live notification.

## Dashboards

Three widgets are available in custom dashboards: **Defense coverage by tactic**, **Top uncovered techniques used by threats** and **Techniques by defense level** (the number of techniques with a deployed detection, of validated techniques, and the techniques per level). Like the matrix, they show the levels computed from the evidences the reader can access.

Click **Create the defense coverage dashboard** in the defense matrix header to create a custom dashboard from the built-in template: coverage by tactic, uncovered techniques used by threats, techniques by defense level, and detection rules by pattern type with the latest ones. The same template is offered on the custom dashboards page: click **Create from template** and choose **Defense coverage**.

The defense widgets are not available in public dashboards and in the custom views of entities.

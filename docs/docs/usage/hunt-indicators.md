# Indicator hunts

An indicator hunt looks for a list of values in the telemetry of your security platforms: IP addresses, domains, URLs, file hashes. It needs no query language: the hunt connector of each platform turns the list into lookups. To create a first one, see [Your first hunt](your-first-hunt.md).

## What an indicator hunt looks for

The values of an indicator hunt add up from four sources, edited in the **What to look for** card of its **Logic** tab:

| Source | Description |
|---|---|
| Indicators and observables | Picked from a list. An indicator brings the values of the equality comparisons of its STIX pattern (`[ipv4-addr:value = '198.51.100.7']`, `[file:hashes.'SHA-256' = '...']`); an observable brings its value, every hash for a file. |
| Take them from | Reports, groupings and incident responses bring the indicators and observables they contain; intrusion sets, malware, tools, campaigns, threat actors and incidents bring the indicators that indicate them and the observables related to them. Revoked indicators are left out. |
| Paste values | Values pasted as text, one per line or separated by commas, semicolons or spaces. The type of each value is detected and checked by the platform; defanged values (`hxxp`, `[.]`, `(.)`, `[@]`) are restored. |
| Or the ones matching a filter | The indicators and observables matching a filter, for example the indicators labelled `apt28` that are still valid. |

The values are read again at **every run**: a hunt taken from a report or a threat follows the intelligence of the moment. The **Values the next run looks for** card lists them, with the indicators and observables each comes from.

Supported types: IPv4 and IPv6 addresses, domain names, host names, URLs, email addresses, MAC addresses and file hashes (MD5, SHA-1, SHA-256, SHA-512). Domains, host names, email addresses and hashes are compared without case; URLs keep their case.

### What is left out

| Case | Shown as |
|---|---|
| An indicator or observable more restricted than the hunt: one of its markings is not covered by a marking of the hunt of the same type and level, or it is not shared with every organization the hunt is shared with (with a platform organization, an object shared with no organization is readable by the platform organization only), or it is restricted to authorized members, which a hunt cannot be | "3 indicators or observables are more restricted than the hunt and are left out: raise the markings of the hunt" |
| A report, grouping or incident response restricted to authorized members (shared with selected users or groups): what it contains is for its members only, so the hunt takes nothing from it | Its indicators and observables are not listed in the values of the hunt |
| An indicator without a value a lookup can search: a pattern in another language (Sigma, YARA...) or without an equality comparison | "2 indicators have no value a lookup can search: a pattern in another language or without an equality comparison" |
| More than 1,000 values (`hunt_manager:max_iocs_per_run`). The indicators and observables chosen, the sources taken from and the filter are read in turn, 1,001 indicators and observables at most for all of them together, so a hunt with many sources reads the first ones only. A hunt has at most as many sources as that limit: saving more is refused | "Only the first 1000 values are looked for: narrow the list" |

The first rule guarantees that a run never discloses an indicator to the readers of the hunt who could not read it: such an indicator is not sent to the hunt connector either, so it is neither looked for nor sighted, whatever the type of the hunt. A hunt whose values all disappear (indicators revoked, removed or more restricted) does not run: "None of the indicators and observables of this hunt has a value a lookup can search: add values or other indicators".

## How a run works

1. The platform resolves the values of the hunt when the run is dispatched and keeps them on the run.
2. The hunt connector groups them by observable type in batches of 50 values (`hunt_manager:ioc_batch_size`) and runs one lookup per batch over the time window of the run, the **look back** of the hunt (24 hours, 7 days, 30 days, or any number of hours up to 720). **Preview the query** shows these lookups without running them.
3. It reports, for each value: seen or not, the number of events holding it, the first and last of them, and up to ten hosts; or not searched, with the reason, when the platform cannot look up that type.
4. It reports the keys of the hits holding each value. OpenCTI keeps one **sighting** per hunt, indicator or observable a seen value comes from, and security platform, updated in place at each run: its count holds the distinct hits of its values found so far, its dates the first and the latest hit, and it carries the markings and organizations of the run (see [Access rights](hunts.md#access-rights)). A pasted value is created as an observable by the connector, so that OpenCTI can sight it. A lookup that returns counts instead of events adds the hits of each run to the count.

Only hunt connectors that look up indicators run indicator hunts. The Splunk hunt connector does; the others run detection rule hunts. The checklist of the hunt says when no hunt connector of its scope supports indicator lookups.

## Results and verdicts

The run drawer lists **Results per value**, the seen values first:

| Verdict per value | Meaning |
|---|---|
| Seen | Found: hits, first and last seen, hosts, the indicators and observables it comes from. |
| Not seen | Searched over the period, not found. |
| Not searched | The platform cannot look up this type of value; the reason is shown. |

The verdict of the run follows the rules of every hunt: with a value seen, the run waits for your verdict (true positive, benign or inconclusive), and from the escalation threshold of the hunt it proposes an incident. Without any value seen, the run is **Benign** only if every value was searched and the results are complete; otherwise it is **Inconclusive**, since a value not searched proves nothing.

When an indicator of a seen value is deployed on the hunted platform (dissemination assurance, which records where indicators are deployed), its row shows **Deployed on this platform**: the hunt confirms the indicator is seen where it is deployed.

## For hunt connector developers

Indicator hunts extend the `INTERNAL_HUNT` contract:

- the run message carries `hunt.hunt_type = "indicators"`, `hunt.iocs` (`key`, `observable_type`, `hash_algorithm`, `value`, `sources` with their STIX ids) and `limits.ioc_batch_size`;
- the report (`huntRunReport`, pycti `report_hunt_run(ioc_results=...)`) carries `ioc_results`, one per key: `seen`, `searched`, `hits_count`, `first_seen`, `last_seen`, `hosts`, `reason`. A value the report leaves out is recorded not searched;
- a connector declares the capability at registration (`huntConnectorRegister(supports_indicators: true)`, pycti `register_hunt_platform(supports_indicators=True)`).

With the connectors SDK, override `ioc_query(batch)` on `InternalHuntConnector`: the base batches the values, runs the lookups within the run deadline, finds the values in the returned events (or reads one aggregated row per value with `ioc_aggregated = True`), reports the results with the keys of the hits of each value, and sends the observables of the pasted values.

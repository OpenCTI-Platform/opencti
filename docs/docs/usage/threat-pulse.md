# Threat Pulse

Threat Pulse is the collective intelligence network of the OpenCTI community, run through [XTM Hub](../administration/hub.md). It tells analysts how widespread an indicator, an attack pattern, a vulnerability, an intrusion set, a malware or a tool is across the community, since when the network sees it and whether it is rising, and it tells managers what trends in their sector and how their platform compares with the sector median.

Platforms that contribute send keyed hashes and activity counts of the objects they observe, never values. XTM Hub publishes a signal only when enough distinct platforms observed the same object (k-anonymity, 5 platforms by default).

Threat Pulse is available in the Community Edition. The Sector benchmark and the Sector Pulse Briefing require the Enterprise Edition. No AI is involved, except in the optional briefing.

## The three modes

An administrator chooses the mode of the platform in "Settings > Filigran Experience". Every change is recorded in the audit logs.

| Mode | What the platform shows | What leaves the platform |
|:-----|:------------------------|:-------------------------|
| **Preview** (default) | The coarse community signal of the local objects that are among the most prevalent of the community: prevalence and trend only, labelled "Preview". The first three ranks of "Trending in your sector". | **Nothing.** The platform downloads the daily digest and matches it locally. |
| **Contribute** (full experience) | Everything: prevalence, range of contributing platforms, network first and last seen, 12-week trend, sector trend, community uniqueness, the full "Trending in your sector" list, the Sector benchmark (Enterprise Edition), the "Trending in my sector" triggers and the Sector Pulse Briefing (Enterprise Edition). | Keyed hashes and activity counts of the objects in scope, every hour (see below). |
| **Off** | Nothing. | Nothing. |

A platform that is not registered on XTM Hub shows what Threat Pulse would add and a "Connect to XTM Hub" button to its administrators. A platform that cannot reach XTM Hub is never asked to connect.

### Preview

The preview is on by default on every platform registered on XTM Hub because it sends nothing about the platform's data. Once a day, the platform downloads:

- the salt of the day;
- the digest of its sector and region: the objects (5,000 by default) that the most distinct platforms reported over the last 30 days, each as a hash with its community prevalence and trend only, and the "Trending in your sector" list, whose first three ranks are named and the next ones counted.

The request carries the day and the coarse sector and region buckets of the platform, nothing else. The platform computes the hashes of its own objects locally, matches them against the digest and stores the result on the matching objects. Matching runs on every object in scope, whatever its markings, because nothing leaves the platform.

Local matching works because every platform derives the same hash for the same object. The digest is therefore readable by every connected platform for the values it can name: a platform can test whether a CVE identifier, an ATT&CK technique or a threat name it knows is among the most prevalent objects of the community. This is what the digest publishes, and only for objects that at least `k` platforms reported; it never says which platform reported them.

In preview, every Threat Pulse surface shows the real coarse signal and lists, as locked rows, what contributing would add. It never shows fake or blurred numbers. Administrators get one "Unlock the full Threat Pulse by contributing" button that leads to "Settings > Filigran Experience"; other users are told to ask their administrator.

The first day the preview matches objects of the platform, each user sees one banner with the number of local objects seen across the community. The banner can be dismissed.

### Contribute

Contributing requires an administrator to accept the consent text, which describes exactly what is shared. OpenCTI records the consent with the administrator and the date.

Reciprocity is enforced by XTM Hub, not by the user interface: network lookups, the full trending list and benchmarks are only answered to platforms that contributed recently. A platform is an active contributor while its last contribution is at most 7 days old, and it keeps the full experience for 14 days after its last contribution. Past that grace period, the platform falls back to the preview automatically and "Settings > Filigran Experience" says so; the full experience comes back with the next accepted contribution.

Stopping the contribution ("Stop contributing") switches the platform back to the preview and removes the full statistics from the objects.

## What a contributing platform shares

Every hour, a contributing platform sends to XTM Hub one record per object, activity kind and day:

| Field | Content |
|:------|:--------|
| `hash` | 32 hexadecimal characters derived from the object, encrypted under the salt of the day. Never a value, a name or an identifier. |
| `object_type` | `indicator`, `attack_pattern`, `vulnerability`, `intrusion_set`, `malware` or `tool` |
| `event_kind` | `created`, `sighted`, `detected`, `hunted` or `referenced` |
| `count` | How many such events the platform recorded that day |
| `sector_bucket`, `region_bucket` | The coarse buckets chosen by the administrator, or `undisclosed` |
| `batch_id` | A random identifier drawn for each batch of records and sent again when the batch is retried, so that XTM Hub counts it once |

The batch schema accepts no other field, on the platform and on XTM Hub. A batch that XTM Hub did not answer stays on the platform and is sent again with the next hourly run, with the same identifier.

The hash is derived in two steps:

1. A stable keyed hash of the normalized value (indicators and observables), of the MITRE ID (attack patterns), of the CVE identifier (vulnerabilities) or of the normalized name and each alias (intrusion sets, malware, tools). Every OpenCTI platform derives the same key for the same object, which is what lets the network match it. The key itself is never sent, only its encryption of the day (step 2).
2. The stable key is encrypted with the salt that XTM Hub draws every UTC day and serves to connected platforms only. The hashes sent therefore change every day: hashes recorded on different days (a proxy log, a copy of request bodies) cannot be linked to each other or to an object without the salts of those days, which XTM Hub deletes after 3 days. The salt is not a secret among connected platforms, and every platform derives the same stable key for the same object: a connected platform that knows a value can compute its hash for a day, exactly as the preview does. The request bodies are protected in transit by TLS, and what XTM Hub publishes is protected by k-anonymity, not by the salt.

XTM Hub re-keys every received hash with a key only it holds, stores platform identifiers as pseudonyms, deletes contributions after 13 months and never logs Threat Pulse requests. The details are in the XTM Hub documentation.

Never shared:

- raw values, names, descriptions, files and relationships;
- objects marked `TLP:RED`, `TLP:AMBER+STRICT` or `PAP:RED` (always excluded), objects with restricted access, and objects carrying a marking the administrator excluded;
- the identity of the organization: XTM Hub only knows the registered platform.

## Configure Threat Pulse

In "Settings > Filigran Experience", the Threat Pulse card shows the mode and, for administrators:

- **Mode**: preview, contribute (opens the consent) or off.
- **Sector bucket** and **region bucket**: the coarse buckets used for sector trends and benchmarks, suggested from the platform organization. Choose "Undisclosed" to share none.
- **Scopes**: the object types that contribute (all six by default).
- **Excluded markings**: markings whose objects never contribute, in addition to the ones always excluded.
- **Statistics**: in preview, the number of local objects found in the community digest and the last refresh; when contributing, the records contributed per type, the contribution status (active, grace period, lapsed) and the anonymity threshold.
- **Purge my contributions**: deletes every contribution of the platform from XTM Hub, which recomputes its statistics. This is the right to purge; it is recorded in the audit logs.

Changing the Threat Pulse settings and purging require the "Manage XTM Hub" capability.

## Where Threat Pulse appears

### Threat Pulse card

The overview of indicators, attack patterns, vulnerabilities, intrusion sets, malware and tools shows a "Threat Pulse" card in the right column, after the Basic information and Sources cards:

- **Full**: the community prevalence gauge (rare, uncommon, common, widespread), the range of contributing platforms, the network first and last seen dates, the 12-week trend sparkline, the sector trend and the community uniqueness. An object below the anonymity threshold is reported as such, without any count.
- **Preview**: the prevalence and trend when the object is in the digest, otherwise a short note, then the locked rows "Contributing platforms", "Network first seen", "Community trend over 12 weeks" and "Sector trend", and the unlock step.
- **Not connected**: what Threat Pulse would add and the "Connect to XTM Hub" button.

The card is not displayed when Threat Pulse is off.

### Filters, columns and exports

The objects in scope carry the following attributes, available as filters, sort keys and widget attributes: "Community prevalence" (`pulse_prevalence`), "Community trend" (`pulse_trend`), "Sector trend" (`pulse_sector_trend`), "Network first seen" (`pulse_first_seen_network`) and "Community uniqueness" (`pulse_community_uniqueness`). Prevalence and trend filters also work in preview. Lists of a Priority Intelligence Requirement can be sorted by community prevalence.

These values are written without creating a history entry, a stream event or a modification date change. They are exported in the STIX representation of the six types, in the OpenCTI extension (`pulse_prevalence`, `pulse_trend`, `pulse_sector_trend`, `pulse_first_seen_network`, `pulse_community_uniqueness`, and `pulse_preview: true` when the values come from the preview), and reach streams and feeds with the next update of the object.

### Trending in your sector

"Trending in your sector" is a widget of the dashboard catalog. It lists the local objects rising in the platform's sector over 7, 30 or 90 days, with their prevalence, range of platforms and growth, and says how many trending objects the platform does not hold. In preview, it names the first three ranks and shows the next ones as locked rows. It is not added to the default home dashboard.

### Sector benchmark (Enterprise Edition)

The "Sector benchmark" template, offered in the dashboard creation, creates a dashboard with the trending widget and the benchmark widget: the activity of the platform per object type and activity kind compared with the median of its sector, and the objects it reports well above that median. In preview, the template stays available and its benchmark tiles name what they would show once the platform contributes.

### Notifications

Live triggers can listen to the "Trending in my sector (Threat Pulse)" event type. See [Notifications and alerting](notifications.md).

### Sector Pulse Briefing (Enterprise Edition)

When XTM One is configured, the "Trending in your sector" widget of a contributing platform offers a weekly sector briefing written by the Sector Pulse Briefing agent of XTM One from the trending list and the local context. The briefing is not offered in preview; an XTM One assignment that runs the agent for a platform in preview receives an explanation of what the preview shows and what contributing unlocks instead of a briefing.

## Usage telemetry

The [usage telemetry](../reference/usage-telemetry.md) counts the Threat Pulse mode of the platform, the number of records and lookups sent, the preview impressions and calls to action per surface and the mode changes. No hash and no knowledge content is ever collected.

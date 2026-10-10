# Ingestion Health — Chunk 1 Brainstorm

> Status: **brainstorm**, no code. The step-by-step implementation plan is
> `docs/superpowers/plans/2026-10-07-ingestion-health-chunk-1.md`.
> Sources: Notion TAS-1415 › « Brainstorm chunk 1: Health check minimal version », RFC 0001 (`filigran-private` PR #229), issue #18305, PO decisions of 2026-10-07 and 2026-10-08.

## 1. Goal

Deliver the **full workflow once, at its smallest**:
- **2 configuration checks**: the connector user is not a service account, or the connector user is missing;
- **1 runtime check**: the connector stopped pinging;
- the result shown as **chips in the UI**;
- **no notification yet**.

Everything is behind the `INGESTION_HEALTH` feature flag, in a single PR (backend and front) for #18305.

Why this shape: the later chunks (feeds, more checks, notifications) only add checks and outputs to a pipeline that already works end to end.

## 2. Scope of chunk 1

**In:** every **deployed connector**, whatever its type: import, enrichment, file import/export, analysis, notification, stream. Managed by the composer or self-hosted.

**Out of chunk 1:**
- the platform's built-in connectors: CSV mapper import, draft validation, internal queues, the hidden connectors behind feeds. No process deploys them and they never ping;
- feeds (RSS, CSV, JSON, TAXII) and syncs. They belong to the feature, but come in a later chunk;
- events and notifications (chunk 2);
- `TOKEN_EXPIRED`;
- any change to the authentication path.

The design must leave room for feeds: the status model, the stored fields and the chip must not be connector-specific.

## 3. Two axes, never mixed

|                    | Runtime check                                                          | Configuration check                          |
|--------------------|------------------------------------------------------------------------|----------------------------------------------|
| Chunk 1 check      | `NO_HEARTBEAT`: no ping                                                | `USER_NOT_SERVICE_ACCOUNT`                   |
| Question           | Is the connector working right now?                                    | Is the connector set up correctly?           |
| Computed by        | The **ingestion health manager**, at each cycle (60 s by default)      | A **GraphQL resolver**, at **each API call** |
| Stored             | **In Elasticsearch**, on the connector: status, since, summary, checks | **Never**                                    |
| Decides the status | Yes                                                                    | **Never**                                    |
| Shown              | Chip in the Deployed list, the cards and the detail page               | Detail page only, in the chip tooltip        |

Why:
- A runtime check needs history (several pings seen over time). It must also give the same answer to the UI and, later, to the alerts. So there is a single evaluator, run by the manager, whose result everyone else reads.
- A configuration check only reads current data that is cheap to get (the user cache). Recomputing it on every call means the warning disappears the moment an admin fixes the user.

## 4. Statuses

| Status             | When                                                                                                             | In chunk 1                                                               |
|--------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| `stopped`          | A managed connector switched off by a person: its **requested** status is `stopping` or `stopped`. It wins over everything: a source stopped on purpose is never red. A crashed container (requested `starting`, current `stopped`) is **not** stopped: it goes through the heartbeat check. | Produced                                                                 |
| `critical`         | The runtime check fails.                                                                                         | Produced                                                                 |
| `unknown`          | Nothing proves the connector works or fails.                                                                     | Produced                                                                 |
| `healthy`          | Proven to bring data in.                                                                                         | **Never**: a ping proves the connector is alive, not that data comes in. |
| `degraded`, `idle` | For later checks.                                                                                                | Not produced                                                             |

The API exposes all six values from the start, so the list never changes in later chunks.

## 5. The runtime check: `NO_HEARTBEAT`

**Rule:** no ping for **5 minutes or more** → `critical`.
- It is the same threshold as Active/Inactive, so the two always agree. The POC's 10 min is rejected.
- The ping date is the connector's **Redis heartbeat** (`connector_heartbeats`), written by every ping and every registration since #18851. It is the same source as Active/Inactive, read by the manager once per cycle.

**Only for connectors that ping every 40 s.** A long-running pycti connector has a thread that pings every 40 s.
Many legacy run-and-terminate connectors (about 30, e.g. `cape`) behave differently:
- they do not declare `run_and_terminate`;
- they do not start that thread;
- they register at start and ping once or twice at exit, then are silent for hours.

Without a guard, they would turn red between every run.

So a connector is checked only once the manager has seen **3 pings in a row, each at most 2 manager periods after the previous one, and never less than 120 s** (120 s with the default 60 s period).
- With the default period, a live pycti connector shows a new ping 40 to 80 s after the previous one at each cycle, so it qualifies after about 4 minutes.
- The bound follows the period: with a 5 min period, the manager sees a new ping up to about 5 min 40 s after the previous one, so the bound becomes 10 min.
- A legacy run shows at most 2 pings, so it never qualifies, whatever its length and whatever the period.

**Never checked:**
- connectors that declare `run_and_terminate`;
- connectors never seen running;
- connectors the manager has not yet seen pinging every 40 s, for example just after the flag is turned on. This means no burst of false alarms at activation or after a restart.

**Back to normal:** a dead connector that restarts pings long after its last ping, so the count starts again from zero. It shows `unknown` again at the next cycle.

**When the manager itself was not looking.** A platform restart or a lost lock can leave the manager without a cycle for a while. Then the gap between two pings it sees is wide because *it* did not look, not because the connector stopped.
- A **full cycle** is one pass of the manager over every deployed connector. It counts as full as soon as the connector list could be read, even if some connectors failed to evaluate.
- After each full cycle, the manager records **the time that cycle started** in a single Redis key, `ingestion-health-manager-last-run`.
- At the start of the next cycle, it reads that key. If the previous full cycle started more than 2 periods ago (and at least 120 s ago), the manager knows it was blind.
- It then keeps the count of the connectors **already seen pinging every 40 s** (count at 3), instead of restarting it. A connector that was pinging every 40 s and dies right after the outage is therefore still caught.
- Every other count restarts as usual: a newly started connector, and above all a legacy one. Outages can never add up, run after run, into a false proof: a legacy connector's count stays at 2 or less.
- Side effect: a connector that had just started (1 or 2 pings seen) before the outage starts its count again, and is checked a few minutes later.

The same key also tells an operator whether the manager is alive.

## 6. The configuration check: `USER_NOT_SERVICE_ACCOUNT`

- Fires when the connector user is not a service account.
- The message is « User is not a service account », **with no user name**, neither in the message nor in its parameters. Reading a connector only needs the `MODULES` capability, while the name of its user is reserved to `SETTINGS_SETACCESSES`: the platform hides it from everyone else, and the warning must not leak it.
- Advisory only: it never changes the status.
- No user at all → `USER_NOT_SERVICE_ACCOUNT` does not apply; `USER_MISSING` does (below).
- Shown only on the connector detail page, in the chip tooltip, after the runtime explanation.

## 6 bis. The configuration check: `USER_MISSING`

- Fires when the connector has no user: `connector_user_id` is empty, or the user it points to no longer exists (deleted).
- The message is « User is missing », with no user id or name, for the same reason as above.
- Severity `blocking`: a connector without a user cannot authenticate. As every configuration check, it still never changes the status. When the connector stops pinging because of it, the status turns `critical` through `NO_HEARTBEAT`, and the warning tells why on the detail page.
- A connector gets either `USER_MISSING` or `USER_NOT_SERVICE_ACCOUNT`, never both.
- `connector_user_id` is set again at every registration, so a running connector always has one. An empty value only exists on an old record of a connector that has not restarted since.

## 7. How it works

1. **The ingestion health manager** runs every **60 s by default**, with its own lock. The period can be changed in the configuration (`ingestion_health_manager:interval`). The manager is registered only when the flag is on. The « close pings » bound and the « blind manager » threshold both follow the period: 2 periods, never less than 120 s.
2. For each deployed connector, it reads the connector, and what it remembers in **Redis**: the last ping it saw and how many close pings came in a row. Redis keys have no expiry and are deleted with the connector.
3. It evaluates the connector with a **pure function**, with no I/O.
4. **Only when** the status, the summary or the checks change, it writes them on the connector in **Elasticsearch**:
   - `since` moves only when the status changes;
   - the write must not touch `updated_at` (an entity update would also emit a stream event);
   - it must not emit a stream event.
5. **Redis is used by the manager only.** The Deployed list is polled every 5 s per open tab, and a single GraphQL error would break the whole page.
6. **The API** returns the stored runtime verdict as is, and computes the configuration warning at each call.
7. **The front** shows an FDS chip and tooltip. The tooltip text is the server summary, in English and shown as is; only the status label is translated.

## 8. What the user sees

| Where | Chip | Tooltip |
|---|---|---|
| Deployed list, rows | Status | Summary |
| Deployed list, cards | Status | Summary |
| Connector detail page, next to the existing status chip | Status | Summary, « since », other runtime checks, then the configuration warning |

Colors: `critical` in red, `stopped` and `unknown` neutral.

Summaries, in plain words:
- « Not evaluated yet »: the manager has not looked at it yet;
- « No ping every 40 seconds observed, heartbeat not evaluated »: a legacy or newly started connector;
- « Pinging every 40 seconds, data intake not evaluated yet »: alive, but not `healthy`, on purpose;
- « No ping received since <date> »: `critical`;
- « Stopped by a user »;
- « Heartbeat not evaluated for run-and-terminate connectors »;
- « Never seen running ».

These sentences never contain a value that changes with every ping, so the manager only writes on a real change.

## 9. With the flag off

Nothing differs from `master`:
- no manager;
- no Redis key read, written or deleted;
- no stored field;
- both API fields return empty, without error;
- no chip.

## 10. Accepted risks

- **No manager, no fresh status.** If no node runs the manager, the stored status gets old, and nothing in the UI says so. « since » is when the health status last changed, not when the manager last looked. A connector never evaluated says « Not evaluated yet ». One cached `critical` that comes back while the manager is down stays red next to « Active ». Whether the manager runs is visible in Settings › Parameters.
- **A connector already dead when the flag is turned on is never flagged.** The manager never sees it ping, so it stays `unknown` until it restarts. Nothing tells it apart from a legacy connector between two runs. Accepted.
- **Run-and-terminate jobs scheduled at least as often as the close-pings bound** (every 2 minutes or less with the default period). They look like connectors pinging every 40 s, and turn red when their schedule pauses. Rare, accepted. A longer period widens this risk.
- **Lag.** The chip turns red up to one period (60 s by default) after Active/Inactive turns « Inactive », plus the 5 s poll. A longer period means a longer lag, and a longer wait (about 3 periods) before a new connector is checked.
- **A connector deleted during a manager cycle.** The cycle can write its Redis key again right after the deletion removed it, leaving a key with no expiry. Accepted for chunk 1; a later chunk makes sure the key of a deleted connector is gone for good.
- **Leftovers.** Turning the flag on, then off, leaves the Redis keys and the stored fields behind. Nothing reads them, and nothing cleans them up.

## 11. How we will know it works

- A connector silent 299 s is not `critical`; at 300 s it is.
- A connector pinging every 40 s is checked after 3 close pings, never before, with the default period and with a longer one.
- A legacy run of 30 s, 90 s or 10 min never makes the connector `critical`, including between two runs.
- Right after the flag is turned on, no connector is `critical`.
- After a manager outage of several minutes, a connector that was pinging every 40 s and then dies still turns `critical`. A legacy connector still never does, even with outages run after run.
- A stopped managed connector is `stopped`, even with no ping. A crashed managed container (requested `starting`, current `stopped`) turns `critical` once its pings stop.
- The manager write never moves `updated_at`.
- One broken connector does not stop the evaluation of the others, and the error is logged with its id.
- Neither API field ever calls Redis. This is checked by a test, and by watching Redis while the Deployed list is open.
- With the flag off, nothing changes compared with `master`.
- The service account warning shows on the detail page only, and never contains the user name. It disappears as soon as the user becomes a service account, without a restart.
- The manager is disabled in the integration test configuration, so the suite stays deterministic: there, every connector is `unknown` / « Not evaluated yet ». The manager is covered by unit tests, and end to end by the manual run below.
- Manual run: stop a live pycti connector; « Inactive », then a red chip one cycle later; restart it, and the chip goes back to `unknown`.

## 12. At the end of chunk 1

- Update RFC 0001 with the gaps:
  - connectors only;
  - `unknown` instead of `healthy`;
  - two configuration warnings (service account, missing user) instead of three, `TOKEN_EXPIRED` not shipped;
  - the 5 min threshold;
  - the 40 s rule;
  - the manager as the only evaluator.
- Open four follow-up issues:
  - `TOKEN_EXPIRED` without touching authentication;
  - the suspected composer token revocation between connectors sharing a user;
  - the health fields are readable by users with only the `KNOWLEDGE` capability (through `connectorsForImport`/`Export`/`Analysis`), so they can tell whether a connector user is a service account (no name);
  - deleting a connector deletes its Redis key for good, even during a manager cycle.
- Tick the chunk 1 items in Notion.

## 13. Decisions log

| Date | Decision |
|---|---|
| 2026-10-07 | Start from `master`, one PR for backend and front, #18305. The draft and POC branches are reference only. |
| 2026-10-07 | 5 min threshold, aligned on Active/Inactive. Never `healthy`. `stopped` > `critical` > `unknown`. |
| 2026-10-07 | `USER_NOT_SERVICE_ACCOUNT` only, in a separate field, detail page only. `TOKEN_EXPIRED` dropped. Authentication untouched. |
| 2026-10-08 | Every deployed connector, whatever its type. Built-ins excluded. |
| 2026-10-08 | `NO_HEARTBEAT` only for connectors pinging every 40 s. |
| 2026-10-08 | Runtime checks: manager, each cycle, stored in Elasticsearch. Configuration checks: resolver, each API call, never stored. |
| 2026-10-08 | No Redis outside the manager. |
| 2026-10-08 | The ingestion health manager is disabled in `config/test.json`. |
| 2026-10-08 | After a manager outage of more than 2 periods (at least 120 s), only the counts of connectors already seen pinging every 40 s are kept; every other count restarts (`ingestion-health-manager-last-run`, start time of the last full cycle). A connector already dead at activation stays undetected (accepted). |
| 2026-10-08 | A badly written manager period is not handled. Deleting the Redis key of a connector deleted during a cycle: later chunk. |
| 2026-10-08 | The service account warning says « User is not a service account », with no user name (reserved to `SETTINGS_SETACCESSES`). |
| 2026-10-08 | Manager period: 60 s by default, configurable (`ingestion_health_manager:interval`). The close-pings bound and the blind threshold follow it: 2 periods, never less than 120 s. |
| 2026-10-08 | `USER_MISSING` added to chunk 1 (PO): empty `connector_user_id` or deleted user, message « User is missing », severity `blocking`, exclusive with `USER_NOT_SERVICE_ACCOUNT`. |
| 2026-10-08 | Final review: the heartbeat is the Redis `connector_heartbeats` value (#18851), read by the manager once per cycle; if that read fails, the cycle fails and is retried. `stopped` = requested status `stopping`/`stopped` only, so a crashed managed container turns `critical`. |
| 2026-10-08 | Accepted: no fresh status without the manager (`since` = last change of the health status), leftovers after the flag is turned off, run-and-terminate jobs scheduled every ≤ 2 min. PR title free. |

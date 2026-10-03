# Hunt automation

!!! tip "Enterprise edition"

    Scheduled hunts, standing hunts, PIR activation, playbook hunt components and the validation from OpenAEV are available under the **OpenCTI Enterprise Edition** licence. Please read the [dedicated page](../administration/enterprise.md) for full details.

    Manual hunts, manual runs, query tests, verdicts and hunt packs are part of the Community Edition.

An active hunt can run on its own. Automation never bypasses the analyst on what matters: hunts proposed by an agent start as drafts, Incidents are created in draft workspaces, and agent verdicts are proposals. What automation does on its own is limited to running hunts, recording their results (sightings and observed data created by the hunt connectors) and creating Incident drafts.

## Schedules

The **schedule** of a hunt is `manual` (the default), `standing` (see below) or a cron expression, for instance `0 */6 * * *` for every 6 hours. Schedules firing more often than the minimum interval (15 minutes by default) are refused; the creation and edition forms check the interval configured on the platform.

When a scheduled hunt is due, the hunt manager runs it on the platforms of its scope and computes its next occurrence from the current date: occurrences missed during an outage are not replayed. The next run date is displayed on the hunt.

## Standing hunts

A **standing** hunt runs when the knowledge around it moves: a report adds one of its techniques or targets, a new sighting of one of its targets is created, an indicator it relies on is updated. The **trigger filters** of the hunt narrow down the events that start it (for instance, only reports with a given label).

Standing hunts are debounced: a hunt runs at most once per debounce period (15 minutes by default), however many events touch it. When the community trend of a target is rising in Threat Pulse, the debounce of its standing hunts is halved. The knowledge created by hunt runs never triggers standing hunts, so that a hunt never triggers itself.

## Activation by Priority Intelligence Requirements

With **PIR activation**, a hunt is **armed** while at least one of its targets is flagged by a [Priority Intelligence Requirement](pir.md). Arming runs the hunt once; while armed, its schedule and standing triggers apply. When no PIR flags its targets anymore, the hunt is disarmed and waits. Arming never changes the status of the hunt, which remains the analyst's decision.

## Playbooks

Two playbook components orchestrate hunts. See [Playbook components](playbook-components.md).

- **Run hunts** runs hunts for the entities of the bundle: the hunts targeting them, or a fixed list of hunts. It can wait for the results: the playbook execution is suspended until every run of the step is settled (completed, failed or timed out with no retry left), then continues with the bundle, optionally completed with the knowledge produced by the runs. A step whose hunts cannot run continues through its `no-hunt` output.
- **Match hunt results** routes the bundle on the outcome of the hunt runs of the execution: their verdicts (the verdicts proposed by the triage agent can stand for the runs still pending), a minimum number of hits, an Incident draft opened. Bundles that do not match continue through its `no-match` output.

## Validation from OpenAEV

When OpenAEV finishes an inject for a technique on an asset whose security platform is known, it asks OpenCTI to validate the detection: the active hunts covering the technique run on the hunt connector of that security platform, over the execution window of the inject. The request is idempotent per inject, hunt and platform.

When the runs complete, OpenCTI writes the `hunt_detected` coverage on the security coverage of the simulation: 100 when the hunt found the emulated activity, 0 otherwise. This coverage is kept when OpenAEV later updates the security coverage.

## Hunt manager

The hunt manager runs on one platform node at a time. It dispatches the queued runs within the connector budgets, expires the runs a connector never completed, retries failed runs, resumes the playbooks waiting on hunts, applies the run retention and, in Enterprise Edition, starts the scheduled, standing and PIR armed hunts. Manual runs rely on it too, the manager is therefore enabled in every edition.

| Parameter | Environment variable | Default | Description |
|---|---|---|---|
| `hunt_manager:enabled` | `HUNT_MANAGER__ENABLED` | `true` | Enable the hunt manager |
| `hunt_manager:interval` | `HUNT_MANAGER__INTERVAL` | `30000` | Interval between two ticks, in milliseconds |
| `hunt_manager:max_runs_per_tick` | `HUNT_MANAGER__MAX_RUNS_PER_TICK` | `50` | Maximum runs started or processed by one tick of each phase |
| `hunt_manager:automation_page_size` | `HUNT_MANAGER__AUTOMATION_PAGE_SIZE` | `500` | Hunts read per page: due scheduled hunts per tick, and the page size used to evaluate every PIR activated and standing hunt at each tick |
| `hunt_manager:max_concurrent_runs_per_connector` | `HUNT_MANAGER__MAX_CONCURRENT_RUNS_PER_CONNECTOR` | `2` | Runs a hunt connector executes at the same time (a connector may declare a lower limit) |
| `hunt_manager:daily_runs_per_connector` | `HUNT_MANAGER__DAILY_RUNS_PER_CONNECTOR` | `200` | Runs dispatched to a hunt connector per day |
| `hunt_manager:run_timeout_minutes` | `HUNT_MANAGER__RUN_TIMEOUT_MINUTES` | `60` | Time a connector has to complete a run |
| `hunt_manager:preview_timeout_minutes` | `HUNT_MANAGER__PREVIEW_TIMEOUT_MINUTES` | `5` | Time a connector has to translate a query test |
| `hunt_manager:queue_expiry_hours` | `HUNT_MANAGER__QUEUE_EXPIRY_HOURS` | `24` | Time a run waits for an available connector before it is given up |
| `hunt_manager:max_retries` | `HUNT_MANAGER__MAX_RETRIES` | `2` | Automatic retries of a failed or timed out run |
| `hunt_manager:retry_backoff_minutes` | `HUNT_MANAGER__RETRY_BACKOFF_MINUTES` | `10` | Delay before the first retry, doubled at each attempt |
| `hunt_manager:standing_debounce_minutes` | `HUNT_MANAGER__STANDING_DEBOUNCE_MINUTES` | `15` | Minimum delay between two runs of a standing hunt |
| `hunt_manager:min_schedule_interval_minutes` | `HUNT_MANAGER__MIN_SCHEDULE_INTERVAL_MINUTES` | `15` | Minimum interval between two occurrences of a schedule |
| `hunt_manager:max_time_window_hours` | `HUNT_MANAGER__MAX_TIME_WINDOW_HOURS` | `720` | Maximum time window searched by a run |
| `hunt_manager:max_results_per_run` | `HUNT_MANAGER__MAX_RESULTS_PER_RUN` | `10000` | Maximum results a connector returns for a run |
| `hunt_manager:evidence_max_items` | `HUNT_MANAGER__EVIDENCE_MAX_ITEMS` | `20` | Maximum evidence items kept per run |
| `hunt_manager:evidence_max_value_length` | `HUNT_MANAGER__EVIDENCE_MAX_VALUE_LENGTH` | `256` | Maximum length of an evidence value preview |
| `hunt_manager:run_retention_days` | `HUNT_MANAGER__RUN_RETENTION_DAYS` | `365` | Retention of the executed runs |
| `hunt_manager:preview_retention_days` | `HUNT_MANAGER__PREVIEW_RETENTION_DAYS` | `7` | Retention of the query tests |

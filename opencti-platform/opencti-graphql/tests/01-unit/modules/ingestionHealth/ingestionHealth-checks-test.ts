import { describe, expect, it } from 'vitest';
import { DEFAULT_THRESHOLDS } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';
import {
  advanceProductivityCounters,
  buildSummary,
  computeIngestionChecks,
  computeIngestionHealth,
  foldRuntimeStatus,
  resolveRuleProfile,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import type { IngestionHealthInput, IngestionHealthObservation } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';
import { renderCheckMessage, sanitizeCheckDetail } from '../../../../src/modules/ingestionHealth/ingestionHealth-messages';

const NOW = new Date('2026-09-16T12:00:00.000Z');
const ago = (seconds: number) => new Date(NOW.getTime() - seconds * 1000);
const ahead = (seconds: number) => new Date(NOW.getTime() + seconds * 1000);

const HOUR = 3600;
const DAY = 24 * HOUR;

// One fixture per source kind — the profiles are the thing most likely to
// regress, so each kind gets its own baseline.
const scheduledConnector = (over: Partial<IngestionHealthInput> = {}): IngestionHealthInput => ({
  id: 'c1',
  name: 'MISP',
  source_kind: 'connector',
  connector_type: 'EXTERNAL_IMPORT',
  enabled: true,
  last_seen_at: ago(30),
  last_run_at: ago(HOUR),
  next_expected_at: ahead(HOUR),
  expected_period_seconds: 2 * HOUR,
  last_productive_at: ago(HOUR),
  consecutive_empty_runs: 0,
  ...over,
});

const enrichmentConnector = (over: Partial<IngestionHealthInput> = {}): IngestionHealthInput => ({
  id: 'c2',
  name: 'Hygiene',
  source_kind: 'connector',
  connector_type: 'INTERNAL_ENRICHMENT',
  auto: true,
  enabled: true,
  last_seen_at: ago(20),
  queue: { messages_ready: 0, consumers: 1 },
  ...over,
});

const dailyFeed = (over: Partial<IngestionHealthInput> = {}): IngestionHealthInput => ({
  id: 'f1',
  name: 'Daily CSV',
  source_kind: 'feed',
  enabled: true,
  last_run_at: ago(2 * HOUR),
  next_expected_at: ahead(22 * HOUR),
  expected_period_seconds: DAY,
  last_productive_at: ago(2 * HOUR),
  consecutive_empty_runs: 0,
  ...over,
});

const autoFeed = (over: Partial<IngestionHealthInput> = {}): IngestionHealthInput => ({
  id: 'f2',
  name: 'Auto CSV',
  source_kind: 'feed',
  enabled: true,
  // scheduling_period "auto": the feed runs on the manager's own cadence, so it
  // declares neither a period nor a next run.
  last_run_at: ago(10 * 60),
  last_productive_at: ago(10 * 60),
  consecutive_empty_runs: 0,
  ...over,
});

describe('resolveRuleProfile', () => {
  it('judges demand-driven connectors on their queue, never on a schedule', () => {
    const profile = resolveRuleProfile(enrichmentConnector());
    expect(profile.schedule).toBe(false);
    expect(profile.emptyRuns).toBe(false);
    expect(profile.queue).toBe(true);
  });

  it('does not expect a heartbeat from a run_and_terminate connector', () => {
    expect(resolveRuleProfile(scheduledConnector({ run_and_terminate: true })).heartbeat).toBe(false);
  });

  it('never expects a heartbeat or a queue from a feed', () => {
    const profile = resolveRuleProfile(dailyFeed());
    expect(profile.heartbeat).toBe(false);
    expect(profile.queue).toBe(false);
    expect(profile.schedule).toBe(true);
  });
});

describe('liveness', () => {
  it('reports a stale heartbeat as critical', () => {
    const input = scheduledConnector({ last_seen_at: ago(2 * HOUR) });
    const checks = computeIngestionChecks(input, NOW);
    expect(checks.map((c) => c.code)).toContain('NO_HEARTBEAT');
    expect(foldRuntimeStatus(checks, input, NOW)).toBe('critical');
  });

  it('does not report a missing heartbeat for a run_and_terminate connector', () => {
    const input = scheduledConnector({ run_and_terminate: true, last_seen_at: ago(2 * DAY) });
    expect(computeIngestionChecks(input, NOW).map((c) => c.code)).not.toContain('NO_HEARTBEAT');
  });

  it('flags a queue with work waiting and no consumer', () => {
    const input = enrichmentConnector({ queue: { messages_ready: 42, consumers: 0, idle_since: ago(HOUR) } });
    const checks = computeIngestionChecks(input, NOW);
    expect(checks.map((c) => c.code)).toContain('NO_CONSUMER');
    expect(foldRuntimeStatus(checks, input, NOW)).toBe('critical');
  });

  it('stays quiet when the consumer count is unknown — an unreadable broker is not an outage', () => {
    const input = enrichmentConnector({ queue: { messages_ready: 42, consumers: undefined } });
    expect(computeIngestionChecks(input, NOW).map((c) => c.code)).not.toContain('NO_CONSUMER');
  });

  it('leaves an idle enrichment connector alone — nothing to do is not broken', () => {
    const input = enrichmentConnector();
    const checks = computeIngestionChecks(input, NOW);
    expect(checks).toHaveLength(0);
    expect(foldRuntimeStatus(checks, input, NOW)).toBe('healthy');
  });
});

describe('productivity', () => {
  it('is silent while a daily feed is merely not due yet', () => {
    const input = dailyFeed();
    expect(computeIngestionChecks(input, NOW)).toHaveLength(0);
  });

  it('does not call a daily feed overdue two minutes after its due time', () => {
    // The regression this guards: hysteresis counted in evaluation cycles
    // rather than in periods would fire here.
    const input = dailyFeed({ last_run_at: ago(DAY), next_expected_at: ago(120) });
    expect(computeIngestionChecks(input, NOW).map((c) => c.code)).not.toContain('RUN_OVERDUE');
  });

  it('calls a daily feed overdue after two missed runs', () => {
    const input = dailyFeed({ last_run_at: ago(3 * DAY), next_expected_at: ago(2 * DAY + HOUR) });
    const checks = computeIngestionChecks(input, NOW);
    expect(checks.map((c) => c.code)).toContain('RUN_OVERDUE');
    expect(foldRuntimeStatus(checks, input, NOW)).toBe('degraded');
  });

  it('calls a five-minute connector overdue after ten minutes', () => {
    const input = scheduledConnector({
      expected_period_seconds: 300,
      last_run_at: ago(20 * 60),
      next_expected_at: ago(15 * 60),
    });
    expect(computeIngestionChecks(input, NOW).map((c) => c.code)).toContain('RUN_OVERDUE');
  });

  it('treats a failed run as critical, not merely degraded', () => {
    const input = dailyFeed({ last_run_failed: true, last_run_error: 'HTTP 401 Unauthorized' });
    const checks = computeIngestionChecks(input, NOW);
    expect(foldRuntimeStatus(checks, input, NOW)).toBe('critical');
  });

  it('keeps empty runs advisory, never critical', () => {
    const input = scheduledConnector({ consecutive_empty_runs: 5 });
    const checks = computeIngestionChecks(input, NOW);
    expect(checks.map((c) => c.code)).toContain('EMPTY_RUNS');
    expect(checks.every((c) => c.severity === 'advisory')).toBe(true);
    expect(foldRuntimeStatus(checks, input, NOW)).toBe('degraded');
  });

  it('ignores a single empty run', () => {
    expect(computeIngestionChecks(scheduledConnector({ consecutive_empty_runs: 1 }), NOW)).toHaveLength(0);
  });

  it('does not report a feed with no per-run object count as having empty runs', () => {
    // A feed exposes no object count, so EMPTY_RUNS is not observable on one;
    // CURSOR_STALLED carries that signal instead.
    expect(computeIngestionChecks(dailyFeed({ consecutive_empty_runs: 9 }), NOW).map((c) => c.code))
      .not.toContain('EMPTY_RUNS');
  });

  it('leaves an auto feed alone between two of its own runs', () => {
    // The regression this guards: falling back to the evaluation interval gave
    // a two-minute tolerance, so a healthy five-minute feed spent most of its
    // cycle reported as late.
    expect(computeIngestionChecks(autoFeed(), NOW)).toHaveLength(0);
  });

  it('reports an auto feed that has gone quiet, without inventing a due date', () => {
    const input = autoFeed({ last_run_at: ago(4 * HOUR), last_productive_at: ago(4 * HOUR) });
    const checks = computeIngestionChecks(input, NOW);
    expect(checks.map((c) => c.code)).toContain('RUN_STALE');
    expect(checks.map((c) => c.code)).not.toContain('RUN_OVERDUE');
    // The bug this guards: RUN_OVERDUE rendered the same timestamp twice —
    // "Expected to run X, no run since X" — when there was no schedule to quote.
    expect(checks[0].message).toBe(`No run since ${ago(4 * HOUR).toISOString()}`);
  });

  it('flags a stalled cursor only once runs have also been empty', () => {
    const previous = { status: 'healthy' as const, since: ago(3 * DAY).toISOString(), last_cursor_hash: 'abc', consecutive_empty_runs: 3 };
    const moving = dailyFeed({ cursor_hash: 'def', consecutive_empty_runs: 3, previous });
    const stalled = dailyFeed({ cursor_hash: 'abc', consecutive_empty_runs: 3, previous });
    expect(computeIngestionChecks(moving, NOW).map((c) => c.code)).not.toContain('CURSOR_STALLED');
    expect(computeIngestionChecks(stalled, NOW).map((c) => c.code)).toContain('CURSOR_STALLED');
  });
});

describe('stopped and unknown', () => {
  it('reports a disabled source as stopped, not as a failure', () => {
    const input = dailyFeed({ enabled: false, last_run_at: ago(30 * DAY) });
    const checks = computeIngestionChecks(input, NOW);
    expect(foldRuntimeStatus(checks, input, NOW)).toBe('stopped');
  });

  it('reports a never-seen source as unknown rather than healthy', () => {
    const input: IngestionHealthInput = {
      id: 'c9', name: 'New', source_kind: 'connector', connector_type: 'EXTERNAL_IMPORT', enabled: true,
    };
    expect(foldRuntimeStatus(computeIngestionChecks(input, NOW), input, NOW)).toBe('unknown');
  });
});

describe('ranking and summary', () => {
  it('puts the most diagnostic check in the headline', () => {
    const input = dailyFeed({
      last_run_failed: true,
      last_run_error: 'boom',
      consecutive_empty_runs: 5,
      last_run_at: ago(3 * DAY),
      next_expected_at: ago(2 * DAY),
    });
    const checks = computeIngestionChecks(input, NOW);
    expect(checks[0].code).toBe('LAST_RUN_ERROR');
    expect(buildSummary('critical', checks)).toMatch(/^Critical — Last run failed/);
  });

  it('summarises a clean source with the status alone', () => {
    expect(buildSummary('healthy', [])).toBe('Healthy');
  });
});

describe('messages', () => {
  it('substitutes params', () => {
    expect(renderCheckMessage('EMPTY_RUNS', { count: 3 })).toBe('Ran 3 times without importing any object');
  });

  it('never leaves a raw placeholder in a user-visible sentence', () => {
    expect(renderCheckMessage('EMPTY_RUNS', {})).not.toContain('{');
  });

  it('redacts credentials from an error detail', () => {
    const detail = sanitizeCheckDetail('GET https://feed.example.com/api?api_key=SUPERSECRET&page=2 failed');
    expect(detail).not.toContain('SUPERSECRET');
    expect(detail).toContain('[redacted]');
  });

  it('redacts bearer tokens and basic-auth credentials', () => {
    expect(sanitizeCheckDetail('Authorization: Bearer abc.def.ghi')).not.toContain('abc.def.ghi');
    expect(sanitizeCheckDetail('https://user:hunter2@example.com/feed')).not.toContain('hunter2');
  });

  it('truncates a very long detail', () => {
    expect((sanitizeCheckDetail('x'.repeat(5000)) ?? '').length).toBeLessThanOrEqual(501);
  });
});

describe('computeIngestionHealth', () => {
  it('keeps `since` from the previous observation while the status is unchanged', () => {
    const since = ago(3 * HOUR).toISOString();
    const input = scheduledConnector({
      consecutive_empty_runs: 5,
      previous: { status: 'degraded', since, consecutive_empty_runs: 5 },
    });
    const health = computeIngestionHealth(input, NOW, DEFAULT_THRESHOLDS);
    expect(health.status).toBe('degraded');
    expect(health.since?.toISOString()).toBe(since);
  });

  it('resets `since` when the status changes', () => {
    const input = scheduledConnector({
      consecutive_empty_runs: 5,
      previous: { status: 'healthy', since: ago(3 * HOUR).toISOString(), consecutive_empty_runs: 0 },
    });
    expect(computeIngestionHealth(input, NOW).since?.toISOString()).toBe(NOW.toISOString());
  });
});

describe('advanceProductivityCounters', () => {
  // The bug this whole block guards: nothing used to write `last_cursor_hash`
  // or `consecutive_empty_runs` back, so CURSOR_STALLED could never fire and
  // feeds were effectively liveness-only.
  const feedInput = (over: Partial<IngestionHealthInput> = {}): IngestionHealthInput => ({
    id: 'f1', name: 'CSV', source_kind: 'feed', enabled: true, ...over,
  });

  it('starts a feed from scratch when there is no observation', () => {
    const counters = advanceProductivityCounters(
      feedInput({ last_run_at: ago(60), cursor_hash: 'a' }),
      null,
    );
    expect(counters).toEqual({
      last_run_at: ago(60).toISOString(),
      last_cursor_hash: 'a',
      consecutive_empty_runs: 0,
    });
  });

  it('counts an unmoved cursor once per run, not once per evaluation', () => {
    const previous = {
      status: 'healthy' as const,
      since: ago(DAY).toISOString(),
      last_run_at: ago(2 * HOUR).toISOString(),
      last_cursor_hash: 'a',
      consecutive_empty_runs: 1,
    };
    // Same run seen again 60s later: nothing advances.
    const sameRun = advanceProductivityCounters(
      feedInput({ last_run_at: ago(2 * HOUR), cursor_hash: 'a' }),
      previous,
    );
    expect(sameRun.consecutive_empty_runs).toBe(1);

    // A new run with the same cursor: it brought nothing in.
    const newRun = advanceProductivityCounters(
      feedInput({ last_run_at: ago(HOUR), cursor_hash: 'a' }),
      previous,
    );
    expect(newRun.consecutive_empty_runs).toBe(2);
    expect(newRun.last_run_at).toBe(ago(HOUR).toISOString());
  });

  it('resets the count as soon as the cursor moves', () => {
    const previous = {
      status: 'degraded' as const,
      since: ago(DAY).toISOString(),
      last_run_at: ago(2 * HOUR).toISOString(),
      last_cursor_hash: 'a',
      consecutive_empty_runs: 7,
    };
    const counters = advanceProductivityCounters(
      feedInput({ last_run_at: ago(HOUR), cursor_hash: 'b' }),
      previous,
    );
    expect(counters).toEqual({
      last_run_at: ago(HOUR).toISOString(),
      last_cursor_hash: 'b',
      consecutive_empty_runs: 0,
    });
  });

  it('leaves a connector count alone — its works carry a real object count', () => {
    const counters = advanceProductivityCounters(
      scheduledConnector({ consecutive_empty_runs: 4 }),
      { status: 'healthy', since: ago(DAY).toISOString(), consecutive_empty_runs: 99 },
    );
    expect(counters.consecutive_empty_runs).toBe(4);
  });

  it('does not count the very first sighting of a cursor as a still one', () => {
    const counters = advanceProductivityCounters(
      feedInput({ last_run_at: ago(60), cursor_hash: 'a' }),
      { status: 'healthy', since: ago(DAY).toISOString(), last_run_at: ago(HOUR).toISOString(), consecutive_empty_runs: 0 },
    );
    expect(counters.consecutive_empty_runs).toBe(0);
  });

  it('feeds the cursor check a history it can actually act on', () => {
    // End to end: three runs that move nothing reach the threshold, and the
    // check then fires — which it could not do at all before the manager
    // started writing these counters back.
    let previous: IngestionHealthObservation = {
      status: 'healthy',
      since: ago(2 * DAY).toISOString(),
      last_run_at: ago(2 * DAY).toISOString(),
      last_cursor_hash: 'frozen',
      consecutive_empty_runs: 0,
    };
    for (let run = 1; run <= 3; run += 1) {
      const input = dailyFeed({ last_run_at: ago(DAY - run), cursor_hash: 'frozen' });
      previous = { ...previous, ...advanceProductivityCounters(input, previous) };
    }
    expect(previous.consecutive_empty_runs).toBe(3);

    // `buildFeedHealthInput` reads the count back out of the observation.
    const finalInput = dailyFeed({
      cursor_hash: 'frozen',
      consecutive_empty_runs: previous.consecutive_empty_runs,
      previous,
    });
    expect(computeIngestionChecks(finalInput, NOW).map((c) => c.code)).toContain('CURSOR_STALLED');
  });
});

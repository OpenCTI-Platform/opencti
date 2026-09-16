import { describe, expect, it } from 'vitest';
import {
  buildConnectorHealthInput,
  buildFeedHealthInput,
  buildSyncHealthInput,
  formatIngestionLogDetail,
  parseSchedulingPeriodSeconds,
  summarizeWorks,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-domain';

const NOW = new Date('2026-09-16T12:00:00.000Z');
const iso = (secondsAgo: number) => new Date(NOW.getTime() - secondsAgo * 1000).toISOString();
const HOUR = 3600;

const work = (over: Record<string, unknown> = {}) => ({
  status: 'complete',
  completed_time: iso(HOUR),
  completed_number: 10,
  errors: [],
  ...over,
});

describe('summarizeWorks', () => {
  it('finds the most recent productive run', () => {
    const facts = summarizeWorks([
      work({ completed_time: iso(HOUR), completed_number: 0 }),
      work({ completed_time: iso(3 * HOUR), completed_number: 42 }),
    ]);
    expect(facts.last_productive_at?.toISOString()).toBe(iso(3 * HOUR));
  });

  it('counts consecutive empty runs from the most recent backwards', () => {
    const facts = summarizeWorks([
      work({ completed_number: 0 }),
      work({ completed_number: 0 }),
      work({ completed_number: 7 }),
      work({ completed_number: 0 }),
    ]);
    // Stops at the productive run — does not total every empty in the window.
    expect(facts.consecutive_empty_runs).toBe(2);
  });

  it('ignores works that are not complete', () => {
    const facts = summarizeWorks([
      work({ status: 'progress', completed_number: 0 }),
      work({ completed_number: 5 }),
    ]);
    expect(facts.consecutive_empty_runs).toBe(0);
  });

  it('treats a completed work carrying errors as a failed run', () => {
    const facts = summarizeWorks([work({ errors: [{ message: 'HTTP 401' }] })]);
    expect(facts.last_run_failed).toBe(true);
    expect(facts.last_run_error).toBe('HTTP 401');
  });

  it('reports nothing for a connector with no works', () => {
    const facts = summarizeWorks([]);
    expect(facts.last_productive_at).toBeUndefined();
    expect(facts.consecutive_empty_runs).toBe(0);
    expect(facts.last_run_failed).toBe(false);
  });
});

describe('buildConnectorHealthInput', () => {
  const connector = (over: Record<string, unknown> = {}) => ({
    id: 'c1',
    internal_id: 'c1',
    name: 'MISP',
    active: true,
    connector_type: 'EXTERNAL_IMPORT',
    updated_at: iso(30),
    connector_info: { last_run_datetime: iso(HOUR), next_run_datetime: iso(-HOUR), run_and_terminate: false },
    ...over,
  });

  it('derives the expected period from the declared schedule', () => {
    const input = buildConnectorHealthInput(connector(), [work()]);
    // last run 1h ago, next run in 1h → a two-hour cadence.
    expect(input.expected_period_seconds).toBe(2 * HOUR);
  });

  it('leaves the period undefined when the connector declares no next run', () => {
    const input = buildConnectorHealthInput(
      connector({ connector_info: { last_run_datetime: iso(HOUR) } }),
      [work()],
    );
    expect(input.expected_period_seconds).toBeUndefined();
  });

  it('marks a connector the composer was asked to stop as manually stopped', () => {
    const input = buildConnectorHealthInput(connector({ manager_requested_status: 'stopped' }), []);
    expect(input.manually_stopped).toBe(true);
  });

  it('omits the queue entirely when RabbitMQ could not be reached', () => {
    // The evaluator then skips NO_CONSUMER rather than assuming a healthy queue.
    expect(buildConnectorHealthInput(connector(), [], undefined).queue).toBeUndefined();
  });

  it('reads the listen queue, which is the one this connector consumes from', () => {
    // The push queue is drained by workers and says nothing about whether this
    // connector is picking up its own work.
    const input = buildConnectorHealthInput(connector(), [], {
      messages_number: 107,
      listen_messages: 7,
      listen_consumers: 0,
      push_messages: 100,
      push_consumers: 4,
    });
    expect(input.queue).toEqual({ messages_ready: 7, consumers: 0 });
  });

  it('leaves the consumer count unset when the broker answered for no queue', () => {
    // Regression guard: this used to be hardcoded to 1, which made NO_CONSUMER
    // unable to fire at all.
    const input = buildConnectorHealthInput(connector(), [], { messages_number: 0 });
    expect(input.queue).toBeUndefined();
  });

  it('falls back to the last completed work when the connector declares no last run', () => {
    const input = buildConnectorHealthInput(
      connector({ connector_info: null }),
      [work({ completed_time: iso(2 * HOUR) })],
    );
    expect(input.last_run_at?.toISOString()).toBe(iso(2 * HOUR));
  });

  it('carries run_and_terminate through so the heartbeat rule can be skipped', () => {
    const input = buildConnectorHealthInput(
      connector({ connector_info: { run_and_terminate: true } }),
      [],
    );
    expect(input.run_and_terminate).toBe(true);
  });
});

describe('parseSchedulingPeriodSeconds', () => {
  it('parses the ISO-8601 durations feeds actually use', () => {
    expect(parseSchedulingPeriodSeconds('PT1H')).toBe(3600);
    expect(parseSchedulingPeriodSeconds('PT6H')).toBe(6 * 3600);
    expect(parseSchedulingPeriodSeconds('P1D')).toBe(86400);
    expect(parseSchedulingPeriodSeconds('PT30M')).toBe(1800);
  });

  it('returns undefined for "auto" and for empty, so no expectation is imposed', () => {
    expect(parseSchedulingPeriodSeconds('auto')).toBeUndefined();
    expect(parseSchedulingPeriodSeconds('')).toBeUndefined();
    expect(parseSchedulingPeriodSeconds(null)).toBeUndefined();
  });

  it('returns undefined rather than 0 for an unparseable value', () => {
    expect(parseSchedulingPeriodSeconds('every hour')).toBeUndefined();
  });
});

describe('buildFeedHealthInput', () => {
  const feed = (over: Record<string, unknown> = {}) => ({
    id: 'f1',
    name: 'Daily CSV',
    ingestion_running: true,
    scheduling_period: 'P1D',
    last_execution_date: iso(2 * HOUR),
    last_execution_status: 'success',
    current_state_hash: 'abc',
    ...over,
  });

  it('derives the next run from the declared scheduling period', () => {
    const input = buildFeedHealthInput(feed());
    expect(input.expected_period_seconds).toBe(86400);
    expect(input.next_expected_at?.toISOString()).toBe(new Date(NOW.getTime() + 22 * HOUR * 1000).toISOString());
  });

  it('imposes no expectation when the feed schedules itself', () => {
    const input = buildFeedHealthInput(feed({ scheduling_period: 'auto' }));
    expect(input.expected_period_seconds).toBeUndefined();
    expect(input.next_expected_at).toBeUndefined();
  });

  it('treats a stopped feed as manually stopped, not failed', () => {
    const input = buildFeedHealthInput(feed({ ingestion_running: false }));
    expect(input.manually_stopped).toBe(true);
    expect(input.enabled).toBe(false);
  });

  it('trusts the feed’s own reported status for failure', () => {
    expect(buildFeedHealthInput(feed({ last_execution_status: 'error' })).last_run_failed).toBe(true);
    expect(buildFeedHealthInput(feed({ last_execution_status: 'success' })).last_run_failed).toBe(false);
  });

  it('never echoes the literal status as the reason', () => {
    // "Last run failed: error" told the reader nothing. With no log entry to
    // draw on, the renderer says "unknown", which at least does not pretend.
    expect(buildFeedHealthInput(feed({ last_execution_status: 'error' })).last_run_error).toBeUndefined();
  });

  it('carries the readable cause through when one was read', () => {
    const input = buildFeedHealthInput(
      feed({ last_execution_status: 'error' }),
      undefined,
      'Feed fetch failed: Invalid Opening Quote',
    );
    expect(input.last_run_error).toBe('Feed fetch failed: Invalid Opening Quote');
  });

  it('ignores a cause for a feed whose last run succeeded', () => {
    const input = buildFeedHealthInput(feed({ last_execution_status: 'success' }), undefined, 'stale error');
    expect(input.last_run_error).toBeUndefined();
  });

  it('never expects a heartbeat or a queue from a feed', () => {
    const input = buildFeedHealthInput(feed());
    expect(input.queue).toBeUndefined();
    expect(input.last_seen_at).toBeUndefined();
  });
});

describe('buildSyncHealthInput', () => {
  const sync = (over: Record<string, unknown> = {}) => ({
    id: 's1',
    name: 'Remote OpenCTI',
    running: true,
    current_state_date: iso(5 * 60),
    last_execution_date: iso(60),
    last_execution_status: 'success',
    ...over,
  });

  it('uses the stream cursor date as the productivity signal', () => {
    const input = buildSyncHealthInput(sync());
    expect(input.last_productive_at?.toISOString()).toBe(iso(5 * 60));
  });

  it('treats a paused synchronizer as stopped', () => {
    expect(buildSyncHealthInput(sync({ running: false })).manually_stopped).toBe(true);
  });
});

describe('formatIngestionLogDetail', () => {
  const entry = (over: Record<string, unknown> = {}) => ({
    timestamp: Date.now(),
    level: 'error' as const,
    type: 'csv',
    identifier: 'Daily CSV',
    message: 'Feed fetch failed',
    ...over,
  });

  it('renders an HTTP failure with its status', () => {
    expect(formatIngestionLogDetail(entry({ meta: { http_status: 401, http_status_text: 'Unauthorized' } })))
      .toBe('Feed fetch failed: HTTP 401 Unauthorized');
  });

  it('renders a parse failure with the underlying message', () => {
    // `buildIngestionErrorMeta` puts a non-Axios error message under `error`.
    expect(formatIngestionLogDetail(entry({ meta: { error: 'Invalid Opening Quote' } })))
      .toBe('Feed fetch failed: Invalid Opening Quote');
  });

  it('names a Cloudflare challenge, which otherwise looks like a plain 403', () => {
    expect(formatIngestionLogDetail(entry({
      meta: { http_status: 403, cloudflare: 'Cloudflare challenge fail' },
    }))).toBe('Feed fetch failed: HTTP 403 — Cloudflare challenge fail');
  });

  it('falls back to the bare message when there is no usable meta', () => {
    expect(formatIngestionLogDetail(entry({ meta: {} }))).toBe('Feed fetch failed');
    expect(formatIngestionLogDetail(entry())).toBe('Feed fetch failed');
  });
});

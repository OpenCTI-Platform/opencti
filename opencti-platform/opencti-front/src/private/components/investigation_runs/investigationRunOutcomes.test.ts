import { describe, expect, it } from 'vitest';
import { elapsedMs, formatDuration, runReasonNext, runStatusSentence, stepOutcome, type Translate } from './investigationRunOutcomes';
import { draftChangeGroups, draftChangeSummary, type DraftChange } from './investigationRunDraftChanges';

// Fills the placeholders like the platform formatter does, so the tests read the final sentence.
const t: Translate = (message, options) => Object.entries(options?.values ?? {})
  .reduce((text, [key, value]) => text.replace(`{${key}}`, String(value)), message)
  .replace(/\{count, plural, one \{# (\w+)\} other \{# (\w+)\}\}/, (_, one: string, other: string) => (options?.values?.count === 1 ? `1 ${one}` : `${options?.values?.count} ${other}`));

describe('Case Autopilot durations', () => {
  it('measures up to now while the end is not known', () => {
    expect(elapsedMs('2026-10-03T10:00:00.000Z', '2026-10-03T10:04:12.000Z')).toBe(252000);
    expect(elapsedMs('2026-10-03T10:00:00.000Z', null, new Date('2026-10-03T10:00:30.000Z').getTime())).toBe(30000);
    expect(elapsedMs(null, null)).toBeNull();
    expect(elapsedMs('not a date', null)).toBeNull();
  });

  it('formats durations in words', () => {
    expect(formatDuration(12000, t)).toBe('12 s');
    expect(formatDuration(252000, t)).toBe('4 min 12 s');
    expect(formatDuration(240000, t)).toBe('4 min');
    expect(formatDuration(3900000, t)).toBe('1 h 5 min');
    expect(formatDuration(7200000, t)).toBe('2 h');
  });
});

describe('Case Autopilot step outcomes', () => {
  it('says why a step failed and what to do, never a bare state', () => {
    expect(stepOutcome('error', 'source.timed_out', { seconds: 30 }, t)).toEqual({
      text: 'The source did not answer within 30 s.', next: 'run_again', details: 'source.timed_out seconds=30',
    });
    expect(stepOutcome('empty', 'source.enrichment_nothing_to_enrich', {}, t)?.next).toBe('policy_connectors');
    expect(stepOutcome('skipped', 'run.budget_spent', { budget: 'iterations' }, t)?.next).toBe('policy_budget');
    expect(stepOutcome('empty', 'source.enrichment_awaiting_approval', { count: 2 }, t)).toMatchObject({
      text: 'Enrichment jobs waiting for your approval: 2.', next: 'review_approvals',
    });
    expect(stepOutcome('error', 'source.conclusion_unavailable', {}, t)?.next).toBe('xtm_one');
  });

  it('reads HTTP statuses as access, rate and availability problems', () => {
    expect(stepOutcome('error', 'source.http_status', { status: 403 }, t)).toMatchObject({ text: 'Access denied: the source refused the request (HTTP 403).', next: 'xtm_one' });
    expect(stepOutcome('error', 'source.http_status', { status: 429 }, t)?.next).toBe('run_again');
    expect(stepOutcome('error', 'source.http_status', { status: 503 }, t)?.text).toBe('The source is unavailable (HTTP 503).');
    expect(stepOutcome('empty', 'source.http_status', { status: 404 }, t)?.next).toBeNull();
  });

  it('falls back on the state when the code or its parameters are unknown', () => {
    expect(stepOutcome('empty', null, null, t)).toEqual({ text: 'The source answered and found nothing.', next: null, details: null });
    expect(stepOutcome('error', 'source.brand_new', null, t)).toMatchObject({ text: 'The source could not be queried.', next: 'run_again', details: 'source.brand_new' });
    expect(stepOutcome('error', 'source.timed_out', {}, t)).toMatchObject({ text: 'The source could not be queried.', next: 'run_again' });
    expect(stepOutcome('completed', null, null, t)).toBeNull();
    expect(stepOutcome('pending', null, null, t)).toBeNull();
  });
});

describe('Case Autopilot run sentences', () => {
  const base = { run_status: 'running', run_phase: 'investigating', pendingDraftChanges: null, pendingRequests: 0, stepsDone: 2, stepsTotal: 6 };

  it('says what the investigation does and who acts', () => {
    expect(runStatusSentence(base, t)).toBe('Case Autopilot is investigating: 2 of 6 steps done.');
    expect(runStatusSentence({ ...base, stepsTotal: 0 }, t)).toBe('Case Autopilot is investigating.');
    expect(runStatusSentence({ ...base, run_status: 'awaiting_approval', pendingDraftChanges: 5 }, t)).toBe('5 changes are waiting for your review.');
    expect(runStatusSentence({ ...base, run_status: 'awaiting_approval', pendingRequests: 2 }, t)).toBe('Requests waiting for your approval: 2.');
    expect(runStatusSentence({ ...base, run_status: 'completed', draft_status: 'validated' }, t)).toBe('The investigation is complete and its results were written to the case.');
    expect(runStatusSentence({ ...base, run_status: 'failed' }, t)).toBe('The investigation failed.');
  });

  it('names the fix of a run reason', () => {
    expect(runReasonNext(null, 'engine_not_configured')).toBe('ask_administrator');
    expect(runReasonNext(null, 'engine_unreachable')).toBe('run_again');
    expect(runReasonNext('The time budget of the investigation is spent', null)).toBe('policy_budget');
    expect(runReasonNext('Something else', 'other')).toBeNull();
  });
});

describe('Case Autopilot draft changes', () => {
  const changes: DraftChange[] = [
    { kind: 'entity', id: '1', type: 'Intrusion-Set', name: 'APT28', operation: 'create' },
    { kind: 'entity', id: '2', type: 'Note', name: 'Finding', operation: 'create' },
    { kind: 'entity', id: '3', type: 'Case-Incident', name: 'Beaconing', operation: 'update' },
    { kind: 'relationship', id: '4', type: 'indicates', name: 'indicates', fromName: 'APT28', toName: '198.51.100.23', operation: 'create' },
  ];

  it('groups the changes by operation, creations first', () => {
    expect(draftChangeGroups(changes).map((group) => [group.operation, group.changes.length])).toEqual([['create', 3], ['update', 1]]);
  });

  it('summarises the changes by translated type', () => {
    expect(draftChangeSummary(changes, t)).toBe('entity_Case-Incident (1), entity_Intrusion-Set (1), entity_Note (1), Relationships (1)');
  });
});

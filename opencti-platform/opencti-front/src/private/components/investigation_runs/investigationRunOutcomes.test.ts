import { describe, expect, it } from 'vitest';
import { elapsedMs, formatDuration, runReasonNext, runStatusSentence, STEP_OUTCOME_CODES, stepOutcome, type Translate } from './investigationRunOutcomes';
import { draftChangeCount, draftChangeOperation, draftChangeSummary } from './investigationRunDraftChanges';

// Fills the placeholders like the platform formatter does, so the tests read the final sentence.
const t: Translate = (message, options) => {
  const values = options?.values ?? {};
  const pluralized = message.replace(/\{(\w+), plural, (?:one \{([^}]*)\} )?(?:few \{[^}]*\} )?(?:many \{[^}]*\} )?other \{([^}]*)\}\}/g, (_, key: string, one: string | undefined, other: string) => {
    const count = Number(values[key]);
    return (count === 1 && one !== undefined ? one : other).replace('#', String(count));
  });
  return Object.entries(values).reduce((text, [key, value]) => text.split(`{${key}}`).join(String(value)), pluralized);
};

const context = { source: 'Web research', failedSteps: 0, totalSteps: 4, observableTypes: ['IPv4 address'] };

// Every detail code of the investigation engine contract (XTM One `DETAIL_CODES`,
// listed in `dev-docs/investigations.md`): each one must be rendered in words.
const ENGINE_DETAIL_CODES = [
  'run.all_sources_queried', 'run.budget_spent', 'run.time_budget_spent', 'run.no_covering_source', 'run.cancelled', 'run.interrupted',
  'source.timed_out', 'source.http_status', 'source.free_http_refused', 'source.free_http_capped', 'source.truncated',
  'source.thin_response', 'source.querier_error', 'source.kb_provider_unreachable', 'source.kb_search_failed', 'source.kb_capped',
  'source.kb_unavailable', 'source.kb_below_floor', 'source.mcp_bad_server_id', 'source.mcp_server_missing', 'source.mcp_server_disabled',
  'source.mcp_tool_missing', 'source.mcp_argument_ambiguous', 'source.mcp_tool_error', 'source.fingerprint_matched', 'source.fingerprint_capped',
  'source.vt_unavailable', 'source.passive_dns_filtered', 'source.passive_dns_filtered_more', 'source.passive_dns_more', 'source.passive_dns_seeds',
  'source.passive_dns_seeds_set_aside', 'source.opencti_unavailable', 'source.opencti_known', 'source.opencti_none_known', 'source.case_context',
  'source.case_context_empty', 'source.case_run_missing', 'source.enrichment_wave', 'source.enrichment_wave_gaps', 'source.enrichment_wave_capped',
  'source.enrichment_wave_expired', 'source.enrichment_wave_rejected', 'source.enrichment_no_entities', 'source.enrichment_no_connector',
  'source.enrichment_awaiting_approval', 'source.enrichment_refused', 'source.enrichment_timed_out', 'source.conclusion_written',
  'source.conclusion_trimmed', 'source.conclusion_unavailable',
];

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
  it('renders every detail code of the engine contract in words', () => {
    expect(ENGINE_DETAIL_CODES.filter((code) => !STEP_OUTCOME_CODES.includes(code))).toEqual([]);
  });

  it('says why a step failed and what to do, never a bare state', () => {
    expect(stepOutcome('error', 'source.timed_out', { seconds: 30 }, t, context)).toEqual({
      text: 'Web research did not answer within 30 s.', next: 'run_again', also: 'continue', details: 'source.timed_out seconds=30',
    });
    expect(stepOutcome('empty', 'source.enrichment_nothing_to_enrich', {}, t, context)).toMatchObject({
      text: 'No enrichment connector of the policy accepts IPv4 address.', next: 'policy_connectors',
    });
    expect(stepOutcome('empty', 'source.enrichment_nothing_to_enrich', {}, t, { ...context, observableTypes: [] })).toMatchObject({
      text: 'The case holds no observable to enrich.', next: 'add_observables',
    });
    expect(stepOutcome('skipped', 'run.budget_spent', { budget: 10 }, t, context)).toMatchObject({
      text: 'Stopped before this step: the budget of 10 iterations was used.', next: 'continue', also: 'policy_budget',
    });
    expect(stepOutcome('empty', 'source.enrichment_awaiting_approval', { count: 1 }, t, context)?.text).toBe('1 enrichment job is waiting for your approval.');
    expect(stepOutcome('error', 'source.querier_error', {}, t, context)).toMatchObject({ text: 'Web research could not be queried.', next: 'run_again' });
    expect(stepOutcome('degraded', 'source.enrichment_wave_gaps', { jobs: 4, done: 4, gaps: 1, created: 3, updated: 2 }, t, context)).toMatchObject({
      text: '4 of 4 enrichment jobs finished, 1 without a result (failed, refused, skipped or timed out): 3 entities created, 2 updated in the draft.',
      next: 'connectors_status',
    });
    expect(stepOutcome('degraded', 'source.enrichment_wave_capped', { created: 60, updated: 4, cited: 50 }, t, context)?.text)
      .toBe('60 entities created and 4 updated in the draft; the first 50 are cited, the others stay in the draft.');
    // The engine names types by their key and sends durations in seconds.
    const translate: Translate = (message, options) => (message.startsWith('entity_') ? message.replace('entity_', '').replace('-', ' ') : t(message, options));
    expect(stepOutcome('empty', 'source.enrichment_no_connector', { types: 'Domain-Name, IPv4-Addr' }, translate, context)).toMatchObject({
      text: 'No enrichment connector of the policy accepts Domain Name, IPv4 Addr.', next: 'policy_connectors',
    });
    expect(stepOutcome('empty', 'source.enrichment_no_entities', {}, t, context)).toMatchObject({ text: 'The case holds no observable to enrich.', next: 'add_observables' });
    expect(stepOutcome('error', 'source.enrichment_timed_out', { seconds: 600 }, t, context)?.text).toBe('The enrichment jobs did not end within 10 min.');
    expect(stepOutcome('skipped', 'run.time_budget_spent', { seconds: 1800 }, t, context)).toMatchObject({
      text: 'Stopped before this step: the time budget of 30 min was spent.', next: 'run_again', also: 'policy_budget',
    });
  });

  it('explains a missing conclusion by the failed steps when there are some', () => {
    expect(stepOutcome('error', 'source.conclusion_unavailable', {}, t, { ...context, failedSteps: 2 })).toMatchObject({
      text: 'No conclusion - 2 of 4 steps failed, too little evidence to weigh the hypotheses.', next: 'run_again',
    });
    expect(stepOutcome('error', 'source.conclusion_unavailable', {}, t, context)?.next).toBe('xtm_one');
  });

  it('reads HTTP statuses as access, rate and availability problems', () => {
    expect(stepOutcome('error', 'source.http_status', { status: 403 }, t, context)).toMatchObject({ text: 'Access denied by Web research (HTTP 403).', next: 'xtm_one' });
    expect(stepOutcome('error', 'source.http_status', { status: 429 }, t, context)?.next).toBe('run_again_later');
    expect(stepOutcome('error', 'source.http_status', { status: 503 }, t, context)?.text).toBe('Web research is unavailable (HTTP 503).');
    expect(stepOutcome('empty', 'source.http_status', { status: 404 }, t, context)?.next).toBeNull();
  });

  it('falls back on the state when the code or its parameters are unknown', () => {
    expect(stepOutcome('empty', null, null, t, context)).toEqual({ text: 'Web research answered and found nothing.', next: null, also: null, details: null });
    expect(stepOutcome('error', 'source.brand_new', null, t, context)).toMatchObject({ text: 'Web research could not be queried.', next: 'run_again', details: 'source.brand_new' });
    expect(stepOutcome('error', 'source.timed_out', {}, t, context)).toMatchObject({ text: 'Web research could not be queried.', next: 'run_again' });
    expect(stepOutcome('completed', null, null, t, context)).toBeNull();
    expect(stepOutcome('pending', null, null, t, context)).toBeNull();
  });
});

describe('Case Autopilot run sentences', () => {
  const base = {
    run_status: 'running',
    run_phase: 'investigating',
    pendingDraftChanges: null,
    pendingRequests: 0,
    currentStep: { index: 3, total: 6, label: 'Enrich through OpenCTI connectors' },
    stepsFound: 2,
    stepsTotal: 6,
  };

  it('says what the investigation does and who acts', () => {
    expect(runStatusSentence(base, t)).toBe('Step 3 of 6: Enrich through OpenCTI connectors.');
    expect(runStatusSentence({ ...base, currentStep: null }, t)).toBe('Case Autopilot is investigating.');
    expect(runStatusSentence({ ...base, run_status: 'planned' }, t)).toBe('Case Autopilot is preparing the goal plan.');
    expect(runStatusSentence({ ...base, run_status: 'awaiting_approval', pendingDraftChanges: 5 }, t)).toBe('5 changes are waiting for your review.');
    expect(runStatusSentence({ ...base, run_status: 'awaiting_approval', pendingRequests: 2 }, t)).toBe('Requests waiting for your approval: 2.');
    expect(runStatusSentence({ ...base, run_status: 'completed' }, t)).toBe('Complete - 2 of 6 steps found evidence.');
    expect(runStatusSentence({ ...base, run_status: 'failed' }, t)).toBe('The investigation failed.');
  });

  it('names the fix of a run reason', () => {
    expect(runReasonNext(null, 'engine_not_configured')).toBe('ask_administrator');
    expect(runReasonNext(null, 'engine_unreachable')).toBe('run_again');
    expect(runReasonNext('The platform reported 2 error(s) writing the approved changes to the case', 'draft_validation_failed')).toBe('open_draft');
    expect(runReasonNext(null, 'draft_validation_unconfirmed')).toBe('open_draft');
    expect(runReasonNext('The time budget of the investigation is spent', null)).toBe('policy_budget');
    expect(runReasonNext('Something else', 'other')).toBeNull();
  });
});

describe('Case Autopilot draft changes', () => {
  it('folds the linked operations into their own operation', () => {
    expect(['create', 'update', 'update_linked', 'delete', 'delete_linked', null].map(draftChangeOperation))
      .toEqual(['create', 'update', 'update', 'delete', 'delete', 'update']);
  });

  it('summarises the changes from the draft counts, with plurals and without empty groups', () => {
    expect(draftChangeSummary({ entitiesCount: 3, observablesCount: 0, relationshipsCount: 1, sightingsCount: 0, containersCount: 1 }, t))
      .toBe('3 entities, 1 relationship, 1 container');
  });

  it('counts the changes an analyst reviews, never the references the draft total adds', () => {
    expect(draftChangeCount({ entitiesCount: 3, observablesCount: 3, relationshipsCount: 3, sightingsCount: 0, containersCount: 3 })).toBe(12);
    expect(draftChangeCount(null)).toBe(0);
  });
});

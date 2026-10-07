/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import type { InvestigationStepStatusValue } from './investigationRunUtils';

export type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

export const POLICIES_PATH = '/dashboard/settings/customization/case_autopilot';
export const CONNECTORS_PATH = '/dashboard/data/ingestion/connectors';
export const CASE_AUTOPILOT_DOCS_URL = 'https://docs.opencti.io/latest/usage/case-autopilot/';
export const CASE_AUTOPILOT_POLICIES_DOCS_URL = `${CASE_AUTOPILOT_DOCS_URL}#investigation-policies`;
export const XTM_ONE_SETTINGS_PATH = '/dashboard/settings/experience';

// region durations

/** Milliseconds between two instants, up to `now` while the second one is not known. */
export const elapsedMs = (start: string | null | undefined, end: string | null | undefined, now = Date.now()): number | null => {
  if (!start) return null;
  const from = new Date(start).getTime();
  const to = end ? new Date(end).getTime() : now;
  if (Number.isNaN(from) || Number.isNaN(to)) return null;
  return Math.max(0, to - from);
};

/** A duration in words: "12 s", "4 min 12 s", "1 h 5 min". */
export const formatDuration = (ms: number, t: Translate) => {
  const totalSeconds = Math.max(0, Math.round(ms / 1000));
  if (totalSeconds < 60) return t('{seconds} s', { values: { seconds: totalSeconds } });
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes < 60) {
    return seconds > 0 ? t('{minutes} min {seconds} s', { values: { minutes, seconds } }) : t('{minutes} min', { values: { minutes } });
  }
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest > 0 ? t('{hours} h {minutes} min', { values: { hours, minutes: rest } }) : t('{hours} h', { values: { hours } });
};

// endregion

// region run outcomes

// Reasons OpenCTI records on a run (English in the run, translated on screen) and what fixes them.
const RUN_REASON_NEXT: Record<string, StepNextAction> = {
  'The time budget of the investigation is spent': 'policy_budget',
  'The time budget is spent: the investigation concludes with what it found': 'policy_budget',
  'The policy of the run no longer exists': 'open_policies',
  'The identity of the run no longer exists': 'open_policies',
  'The investigated entity is no longer accessible to the identity of the run': 'open_policies',
};

// Why the engine could not run, by end_reason_code, and what fixes it.
const ENGINE_REASON_NEXT: Record<string, StepNextAction> = {
  engine_not_configured: 'ask_administrator',
  engine_disabled: 'ask_administrator',
  engine_unavailable: 'ask_administrator',
  engine_no_agent: 'ask_administrator',
  engine_unreachable: 'run_again',
  'run.time_budget_spent': 'policy_budget',
  draft_validation_failed: 'open_draft',
  draft_validation_unconfirmed: 'open_draft',
};

/** The next action a run's own reason calls for, if any. */
export const runReasonNext = (statusReason: string | null | undefined, endReasonCode: string | null | undefined): StepNextAction | null => {
  if (endReasonCode && ENGINE_REASON_NEXT[endReasonCode]) return ENGINE_REASON_NEXT[endReasonCode];
  if (statusReason && RUN_REASON_NEXT[statusReason]) return RUN_REASON_NEXT[statusReason];
  return null;
};

interface StatusSentenceInput {
  run_status: string;
  run_phase: string;
  draft_status?: string | null;
  pendingDraftChanges: number | null;
  pendingRequests: number;
  // The step running now, or the next one planned.
  currentStep: { index: number; total: number; label: string } | null;
  stepsFound: number;
  stepsTotal: number;
}

/** One sentence saying what the investigation is doing and who is expected to act. */
export const runStatusSentence = (input: StatusSentenceInput, t: Translate) => {
  const { run_status: status, run_phase: phase } = input;
  if (status === 'planned') return t('Case Autopilot is preparing the goal plan.');
  if (status === 'running') {
    if (phase === 'initializing') return t('Case Autopilot is reading the case.');
    if (phase === 'starting') return t('Case Autopilot is starting the investigation in XTM One.');
    if (phase === 'ingesting') return t('Case Autopilot is writing its results to the draft.');
    if (phase === 'validating') return t('The approved changes are being written to the case.');
    const step = input.currentStep;
    if (!step) return t('Case Autopilot is investigating.');
    const label = step.label.includes('{') ? step.label : t(step.label);
    return t('Step {index} of {total}: {label}.', { values: { index: step.index, total: step.total, label } });
  }
  if (status === 'awaiting_approval') {
    if (input.pendingDraftChanges !== null) {
      return input.pendingDraftChanges > 0
        ? t('{count} changes are waiting for your review.', { values: { count: input.pendingDraftChanges } })
        : t('The investigation draft is waiting for your review.');
    }
    return t('Requests waiting for your approval: {count}.', { values: { count: input.pendingRequests } });
  }
  if (status === 'completed') {
    return input.stepsTotal > 0
      ? t('Complete - {found} of {total} steps found evidence.', { values: { found: input.stepsFound, total: input.stepsTotal } })
      : t('The investigation is complete.');
  }
  if (status === 'failed') return t('The investigation failed.');
  if (status === 'cancelled') return t('The investigation was cancelled.');
  return '';
};

// endregion

// region step outcomes

/**
 * What the reader can do about a step that did not find anything: the
 * shared next-action matrix of the investigation surfaces.
 */
export type StepNextAction = 'run_again' | 'run_again_later' | 'continue' | 'policy_connectors' | 'policy_budget' | 'policy_pack' | 'open_policies'
  | 'review_approvals' | 'connectors_status' | 'add_observables' | 'xtm_one' | 'ask_administrator' | 'open_draft';

interface StepOutcomeRule {
  message: string;
  next?: StepNextAction;
  // A second action offered next to the first one.
  also?: StepNextAction;
}

// Every message reads the parameters the engine declares for its code; {source} is the name of the step's source.
const STEP_OUTCOME_RULES: Record<string, StepOutcomeRule> = {
  'run.all_sources_queried': { message: 'Every source of the pack was queried.' },
  'run.budget_spent': { message: 'Stopped before this step: the budget of {budget} iterations was used.', next: 'continue', also: 'policy_budget' },
  'run.time_budget_spent': { message: 'Stopped before this step: the time budget of {duration} was spent.', next: 'run_again', also: 'policy_budget' },
  'run.no_covering_source': { message: 'No source of the pack covers this kind of subject.', next: 'policy_pack' },
  'run.cancelled': { message: 'Stopped before this step: the investigation was cancelled.', next: 'run_again' },
  'run.interrupted': { message: 'The investigation was interrupted before this step.', next: 'run_again' },
  'source.timed_out': { message: '{source} did not answer within {seconds} s.', next: 'run_again', also: 'continue' },
  'source.free_http_refused': { message: 'The pack allows no web request to this address.', next: 'xtm_one' },
  'source.free_http_capped': { message: 'The web requests the pack allows were all used.', next: 'xtm_one' },
  'source.truncated': { message: 'The answer was longer than {max_chars} characters and was cut.' },
  'source.thin_response': { message: '{source} answered with too little content to use ({chars} characters).', next: 'run_again' },
  'source.querier_error': { message: '{source} could not be queried.', next: 'run_again' },
  'source.kb_provider_unreachable': { message: 'The knowledge base cannot be reached.', next: 'xtm_one' },
  'source.kb_search_failed': { message: 'The search in the knowledge base failed.', next: 'run_again' },
  'source.kb_capped': { message: 'Only the {top_k} most relevant passages of the knowledge base were kept.' },
  'source.kb_unavailable': { message: 'The knowledge base of the pack is not available.', next: 'xtm_one' },
  'source.kb_below_floor': { message: 'No passage of the knowledge base was relevant enough ({examined} examined).' },
  'source.mcp_bad_server_id': { message: 'The pack names an MCP server that does not exist.', next: 'xtm_one' },
  'source.mcp_server_missing': { message: 'The pack names an MCP server that does not exist.', next: 'xtm_one' },
  'source.mcp_server_disabled': { message: 'The MCP server {server} is turned off.', next: 'xtm_one' },
  'source.mcp_tool_missing': { message: 'The MCP server {server} has no tool named {tool}.', next: 'xtm_one' },
  'source.mcp_argument_ambiguous': { message: 'The tool {tool} was not called: its arguments are ambiguous.', next: 'xtm_one' },
  'source.mcp_tool_error': { message: 'The tool of the MCP server returned an error.', next: 'run_again' },
  'source.fingerprint_matched': { message: '{matched} of {tested} fingerprints matched.' },
  'source.fingerprint_capped': { message: 'The page was larger than {max_bytes} bytes and was cut.' },
  'source.vt_unavailable': { message: 'VirusTotal is not configured in XTM One.', next: 'xtm_one' },
  'source.passive_dns_filtered': { message: '{kept} of {fetched} passive DNS records were kept.' },
  'source.passive_dns_filtered_more': { message: '{kept} of {fetched} passive DNS records were kept; more exist.' },
  'source.passive_dns_more': { message: 'Only the first {limit} passive DNS records were read.' },
  'source.passive_dns_seeds': { message: '{resolved} of {seeds} names resolved to {ips} addresses; {pivoted} pivots followed.' },
  'source.passive_dns_seeds_set_aside': { message: '{resolved} of {seeds} names resolved to {ips} addresses; {set_aside} set aside.' },
  'source.opencti_unavailable': { message: 'OpenCTI could not be read.', next: 'run_again' },
  'source.opencti_known': { message: '{known} of {checked} entities are already known in OpenCTI.' },
  'source.opencti_none_known': { message: 'None of the {checked} entities is known in OpenCTI.' },
  'source.case_context': { message: 'Read from the case: {entities} entities, {relationships} relationships, {candidates} candidate threats.' },
  'source.case_context_empty': { message: 'The case holds no entity to investigate yet.' },
  'source.case_run_missing': { message: 'The investigation of this case is no longer available in OpenCTI.', next: 'run_again' },
  'source.enrichment_wave': { message: '{done} of {jobs} enrichment jobs ended: {created} entities created, {updated} updated.' },
  'source.enrichment_wave_gaps': {
    message: '{done} of {jobs} enrichment jobs finished, {gaps} without a result (failed, refused, skipped or timed out): {created} entities created, {updated} updated in the draft.',
    next: 'connectors_status',
  },
  'source.enrichment_wave_capped': { message: '{created} entities created and {updated} updated in the draft; the first {cited} are cited, the others stay in the draft.' },
  'source.enrichment_wave_expired': {
    message: 'The enrichment wave reached its deadline: {done} of {jobs} jobs finished, {created} entities created, {updated} updated in the draft.',
    next: 'connectors_status',
  },
  'source.enrichment_wave_rejected': {
    message: 'The enrichment wave was rejected: {done} of {jobs} jobs finished, {created} entities created, {updated} updated in the draft.',
    next: 'open_policies',
  },
  'source.enrichment_no_entities': { message: 'The case holds no observable to enrich.', next: 'add_observables' },
  'source.enrichment_no_connector': { message: 'No enrichment connector of the policy accepts {types}.', next: 'policy_connectors' },
  // Sent by earlier versions of the engine, before the two codes above.
  'source.enrichment_nothing_to_enrich': { message: 'No enrichment connector of the policy accepts {types}.', next: 'policy_connectors' },
  'source.enrichment_awaiting_approval': {
    message: '{count, plural, one {# enrichment job is waiting for your approval.} other {# enrichment jobs are waiting for your approval.}}',
    next: 'review_approvals',
  },
  'source.enrichment_refused': { message: 'The policy refused {count} enrichment jobs.', next: 'open_policies' },
  'source.enrichment_timed_out': { message: 'The enrichment jobs did not end within {duration}.', next: 'connectors_status' },
  'source.conclusion_written': { message: 'Written: {hypotheses} hypotheses and {recommendations} recommendations.' },
  'source.conclusion_trimmed': { message: 'Written: {hypotheses} hypotheses and {recommendations} recommendations; {dropped} set aside because they cited nothing the investigation found.' },
  'source.conclusion_unavailable': { message: 'No conclusion: no language model of XTM One could weigh the hypotheses.', next: 'xtm_one' },
};

/** The codes this view renders in words; any other code falls back on its state's sentence. */
export const STEP_OUTCOME_CODES = [...Object.keys(STEP_OUTCOME_RULES), 'source.http_status'];

const httpStatusRule = (status: number): StepOutcomeRule => {
  if (status === 401 || status === 403) return { message: 'Access denied by {source} (HTTP {status}).', next: 'xtm_one' };
  if (status === 404) return { message: '{source} has nothing at this address (HTTP {status}).' };
  if (status === 429) return { message: '{source} limited the requests (HTTP {status}).', next: 'run_again_later' };
  if (status >= 500) return { message: '{source} is unavailable (HTTP {status}).', next: 'run_again' };
  return { message: '{source} answered with an error (HTTP {status}).', next: 'run_again' };
};

// What a state means when the engine gave no code: never a bare state.
const STATE_FALLBACKS: Partial<Record<InvestigationStepStatusValue, StepOutcomeRule>> = {
  empty: { message: '{source} answered and found nothing.' },
  degraded: { message: '{source} answered only in part.', next: 'run_again' },
  error: { message: '{source} could not be queried.', next: 'run_again' },
  skipped: { message: 'The investigation ended before this step.', next: 'run_again' },
};

export interface StepOutcome {
  text: string;
  next: StepNextAction | null;
  also: StepNextAction | null;
  // The engine's own code and parameters, for "Show details" only.
  details: string | null;
}

/** What the view knows around a step, for the sentences that need more than the engine's parameters. */
export interface StepOutcomeContext {
  source: string;
  // Steps of the run that failed, and all of them, for a conclusion that could not be written.
  failedSteps: number;
  totalSteps: number;
  // Observable types of the case, translated, for an enrichment that found nothing to do.
  observableTypes: string[];
}

const paramValues = (params: unknown): Record<string, string | number> => {
  if (!params || typeof params !== 'object' || Array.isArray(params)) return {};
  return Object.fromEntries(Object.entries(params as Record<string, unknown>)
    .filter((entry): entry is [string, string | number] => typeof entry[1] === 'string' || typeof entry[1] === 'number'));
};

// Rules whose sentence depends on the run rather than on the engine's parameters.
const contextualRule = (code: string | null | undefined, values: Record<string, string | number>, context: StepOutcomeContext): StepOutcomeRule | undefined => {
  if (code === 'source.http_status' && typeof values.status === 'number') return httpStatusRule(values.status);
  if (code === 'source.enrichment_nothing_to_enrich' && context.observableTypes.length === 0) {
    return { message: 'The case holds no observable to enrich.', next: 'add_observables' };
  }
  if (code === 'source.conclusion_unavailable' && context.failedSteps > 0) {
    return { message: 'No conclusion - {failed} of {total} steps failed, too little evidence to weigh the hypotheses.', next: 'run_again' };
  }
  return undefined;
};

/** The outcome of a step in the reader's language, with the next action it calls for. */
export const stepOutcome = (status: string, code: string | null | undefined, params: unknown, t: Translate, context: StepOutcomeContext): StepOutcome | null => {
  const engineValues = paramValues(params);
  const details = code ? [code, ...Object.entries(engineValues).map(([key, value]) => `${key}=${value}`)].join(' ') : null;
  // The engine names entity types by their key: they are read in the reader's language.
  const engineTypes = typeof engineValues.types === 'string'
    ? engineValues.types.split(',').map((type) => type.trim()).filter((type) => type.length > 0).map((type) => t(`entity_${type}`))
    : [];
  const values: Record<string, string | number> = {
    ...engineValues,
    source: context.source,
    failed: context.failedSteps,
    total: context.totalSteps,
    types: (engineTypes.length > 0 ? engineTypes : context.observableTypes).join(', '),
    // Durations the engine sends in seconds.
    ...(typeof engineValues.seconds === 'number' ? { duration: formatDuration(engineValues.seconds * 1000, t) } : {}),
  };
  const rule = contextualRule(code, engineValues, context) ?? (code ? STEP_OUTCOME_RULES[code] : undefined) ?? STATE_FALLBACKS[status as InvestigationStepStatusValue];
  if (!rule) return null;
  // A message whose parameters did not arrive is replaced by the state's own sentence.
  const placeholders = Array.from(rule.message.matchAll(/\{(\w+)[,}]/g)).map((match) => match[1]);
  if (placeholders.some((key) => values[key] === undefined || values[key] === '')) {
    const fallback = STATE_FALLBACKS[status as InvestigationStepStatusValue];
    if (!fallback) return null;
    return { text: t(fallback.message, { values }), next: rule.next ?? fallback.next ?? null, also: null, details };
  }
  return { text: t(rule.message, { values }), next: rule.next ?? null, also: rule.also ?? null, details };
};

// endregion

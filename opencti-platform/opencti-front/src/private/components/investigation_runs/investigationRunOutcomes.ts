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
  stepsDone: number;
  stepsTotal: number;
}

/** One sentence saying what the investigation is doing and who is expected to act. */
export const runStatusSentence = (input: StatusSentenceInput, t: Translate) => {
  const { run_status: status, run_phase: phase } = input;
  if (status === 'planned') return t('Case Autopilot is preparing the investigation.');
  if (status === 'running') {
    if (phase === 'initializing') return t('Case Autopilot is reading the case.');
    if (phase === 'starting') return t('Case Autopilot is starting the investigation in XTM One.');
    if (phase === 'ingesting') return t('Case Autopilot is writing its results to the draft.');
    if (phase === 'validating') return t('The approved changes are being written to the case.');
    return input.stepsTotal > 0
      ? t('Case Autopilot is investigating: {done} of {total} steps done.', { values: { done: input.stepsDone, total: input.stepsTotal } })
      : t('Case Autopilot is investigating.');
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
    if (input.draft_status === 'validated') return t('The investigation is complete and its results were written to the case.');
    return t('The investigation is complete. Its draft stays open for review.');
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
export type StepNextAction = 'run_again' | 'policy_connectors' | 'policy_budget' | 'policy_pack' | 'open_policies' | 'review_approvals' | 'connectors_status'
  | 'xtm_one' | 'ask_administrator';

interface StepOutcomeRule {
  message: string;
  next?: StepNextAction;
}

// Every message reads the parameters the engine declares for its code.
const STEP_OUTCOME_RULES: Record<string, StepOutcomeRule> = {
  'run.all_sources_queried': { message: 'Every source of the pack was queried.' },
  'run.budget_spent': { message: 'Stopped before this step: the budget of the investigation was used.', next: 'policy_budget' },
  'run.no_covering_source': { message: 'No source of the pack covers this kind of subject.', next: 'policy_pack' },
  'run.cancelled': { message: 'Stopped before this step: the investigation was cancelled.', next: 'run_again' },
  'run.interrupted': { message: 'The investigation was interrupted before this step.', next: 'run_again' },
  'source.timed_out': { message: 'The source did not answer within {seconds} s.', next: 'run_again' },
  'source.free_http_refused': { message: 'The pack allows no web request to this address.', next: 'xtm_one' },
  'source.free_http_capped': { message: 'The web requests the pack allows were all used.', next: 'xtm_one' },
  'source.truncated': { message: 'The answer was longer than {max_chars} characters and was cut.' },
  'source.thin_response': { message: 'The source answered with too little content to use ({chars} characters).', next: 'run_again' },
  'source.querier_error': { message: 'The source could not be queried: XTM One reported an error.', next: 'xtm_one' },
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
  'source.enrichment_nothing_to_enrich': { message: 'No enrichment connector of the policy accepts the entities of this case.', next: 'policy_connectors' },
  'source.enrichment_awaiting_approval': { message: 'Enrichment jobs waiting for your approval: {count}.', next: 'review_approvals' },
  'source.enrichment_refused': { message: 'Enrichment jobs refused by the policy: {count}.', next: 'policy_connectors' },
  'source.enrichment_timed_out': { message: 'The enrichment jobs did not end within {seconds} s.', next: 'connectors_status' },
  'source.conclusion_written': { message: 'Written: {hypotheses} hypotheses and {recommendations} recommendations.' },
  'source.conclusion_trimmed': { message: 'Written: {hypotheses} hypotheses and {recommendations} recommendations; {dropped} set aside because they cited nothing the investigation found.' },
  'source.conclusion_unavailable': { message: 'No conclusion: no language model of XTM One could weigh the hypotheses.', next: 'xtm_one' },
};

const httpStatusRule = (status: number): StepOutcomeRule => {
  if (status === 401 || status === 403) return { message: 'Access denied: the source refused the request (HTTP {status}).', next: 'xtm_one' };
  if (status === 404) return { message: 'The source has nothing at this address (HTTP {status}).' };
  if (status === 429) return { message: 'The source limited the number of requests (HTTP {status}).', next: 'run_again' };
  if (status >= 500) return { message: 'The source is unavailable (HTTP {status}).', next: 'run_again' };
  return { message: 'The source answered with an error (HTTP {status}).', next: 'run_again' };
};

// What a state means when the engine gave no code: never a bare state.
const STATE_FALLBACKS: Partial<Record<InvestigationStepStatusValue, StepOutcomeRule>> = {
  empty: { message: 'The source answered and found nothing.' },
  degraded: { message: 'The source answered only in part.', next: 'run_again' },
  error: { message: 'The source could not be queried.', next: 'run_again' },
  skipped: { message: 'The investigation ended before this step.', next: 'run_again' },
};

export interface StepOutcome {
  text: string;
  next: StepNextAction | null;
  // The engine's own code and parameters, for "Show details" only.
  details: string | null;
}

const paramValues = (params: unknown): Record<string, string | number> => {
  if (!params || typeof params !== 'object' || Array.isArray(params)) return {};
  return Object.fromEntries(Object.entries(params as Record<string, unknown>)
    .filter((entry): entry is [string, string | number] => typeof entry[1] === 'string' || typeof entry[1] === 'number'));
};

/** The outcome of a step in the reader's language, with the next action it calls for. */
export const stepOutcome = (status: string, code: string | null | undefined, params: unknown, t: Translate): StepOutcome | null => {
  const values = paramValues(params);
  const details = code ? [code, ...Object.entries(values).map(([key, value]) => `${key}=${value}`)].join(' ') : null;
  let rule = code ? STEP_OUTCOME_RULES[code] : undefined;
  if (code === 'source.http_status' && typeof values.status === 'number') rule = httpStatusRule(values.status);
  if (!rule) rule = STATE_FALLBACKS[status as InvestigationStepStatusValue];
  if (!rule) return null;
  // A message whose parameters did not arrive is replaced by the state's own sentence.
  const placeholders = Array.from(rule.message.matchAll(/\{(\w+)\}/g)).map((match) => match[1]);
  if (placeholders.some((key) => values[key] === undefined)) {
    const fallback = STATE_FALLBACKS[status as InvestigationStepStatusValue];
    if (!fallback) return null;
    return { text: t(fallback.message), next: rule.next ?? fallback.next ?? null, details };
  }
  return { text: placeholders.length > 0 ? t(rule.message, { values }) : t(rule.message), next: rule.next ?? null, details };
};

// endregion

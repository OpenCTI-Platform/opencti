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

// Contract with the XTM One investigation engine (XTM One dev-docs/investigations.md).
// OpenCTI starts one engine run per Investigation-Run, mirrors its goal plan,
// steps and evidence, then grounds its conclusion here before anything is
// written: the engine proposes, OpenCTI decides what survives and scores it.

import { createHash } from 'node:crypto';
import {
  InvestigationEvidenceKind,
  InvestigationRecommendationActionKind,
  InvestigationRecommendationPriority,
  InvestigationRecommendationStatus,
  InvestigationRunTrigger,
  InvestigationStepStatus,
} from '../../generated/graphql';
import {
  INVESTIGATION_DEFAULT_PACK,
  INVESTIGATION_LIMITS,
  INVESTIGATION_START_SCHEMA,
  type BasicStoreEntityInvestigationPolicy,
  type BasicStoreEntityInvestigationRun,
  type InvestigationEvidence,
  type InvestigationRecommendation,
  type InvestigationReportSource,
  type InvestigationStep,
} from './investigationRun-types';
import { clampConsistency, isEvidenceCategory, type AchCellInput, type AchHypothesisInput } from './investigationRun-ach';

// region context sent to the engine

export interface EngineContextEntity {
  id: string;
  standard_id?: string | null;
  entity_type: string;
  name?: string | null;
  description?: string | null;
  created?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  confidence?: number | null;
  author_reliability?: string | null;
}

export interface EngineContextRelationship {
  id: string;
  standard_id?: string | null;
  relationship_type: string;
  from_id: string;
  to_id: string;
  first_seen?: string | null;
  last_seen?: string | null;
  confidence?: number | null;
}

export interface EngineContextCandidate {
  id: string;
  standard_id?: string | null;
  entity_type: string;
  name: string;
  aliases: string[];
}

export interface EngineContextCourseOfAction {
  id: string;
  standard_id?: string | null;
  name: string;
  x_mitre_id?: string | null;
}

export interface EngineEnrichmentConnector {
  id: string;
  name: string;
  scope: string[];
  requires_approval: boolean;
}

export interface InvestigationEngineContext {
  subject: EngineContextEntity;
  entities: EngineContextEntity[];
  relationships: EngineContextRelationship[];
  candidates: EngineContextCandidate[];
  courses_of_action: EngineContextCourseOfAction[];
  pir: Array<{ id: string; name: string; score: number }>;
  connectors: EngineEnrichmentConnector[];
  allowed_actions: string[];
}

export interface AllowedIds {
  evidence: Set<string>;
  candidates: Set<string>;
  coursesOfAction: Set<string>;
  entities: Set<string>;
  connectors: Set<string>;
  // Internal and standard ids, resolved to the internal id.
  aliases: Map<string, string>;
}

type CandidateInfo = Map<string, { name?: string | null; entity_type?: string | null; standard_id?: string | null }>;

export const buildAllowedIds = (context: InvestigationEngineContext, extraEvidence: Array<{ id: string; standard_id?: string | null }> = []): AllowedIds => {
  const aliases = new Map<string, string>();
  const register = (item: { id: string; standard_id?: string | null }) => {
    aliases.set(item.id, item.id);
    if (item.standard_id) aliases.set(item.standard_id, item.id);
  };
  const evidence = new Set<string>();
  [context.subject, ...context.entities, ...extraEvidence].forEach((entity) => {
    evidence.add(entity.id);
    register(entity);
  });
  context.relationships.forEach((relationship) => {
    evidence.add(relationship.id);
    register(relationship);
  });
  const candidates = new Set<string>();
  context.candidates.forEach((candidate) => {
    candidates.add(candidate.id);
    register(candidate);
  });
  const coursesOfAction = new Set<string>();
  context.courses_of_action.forEach((coa) => {
    coursesOfAction.add(coa.id);
    register(coa);
  });
  const entities = new Set<string>([context.subject.id, ...context.entities.map((entity) => entity.id), ...extraEvidence.map((e) => e.id)]);
  const connectors = new Set<string>(context.connectors.map((connector) => connector.id));
  return { evidence, candidates, coursesOfAction, entities, connectors, aliases };
};

const ENGINE_TRIGGERS: Record<InvestigationRunTrigger, string> = {
  [InvestigationRunTrigger.Manual]: 'manual',
  [InvestigationRunTrigger.Playbook]: 'playbook',
  [InvestigationRunTrigger.CaseRfiCreation]: 'rfi',
};

export interface StartBodyInput {
  run: BasicStoreEntityInvestigationRun;
  policy: BasicStoreEntityInvestigationPolicy;
  agentSlug: string;
  subjectName: string;
  context: InvestigationEngineContext;
  allowed: AllowedIds;
  remainingMinutes: number;
  remainingEnrichmentJobs: number;
  continuesInvestigationId?: string | null;
}

/** The `opencti.investigation.start/v1` body of one engine run. */
export const buildStartBody = (input: StartBodyInput) => {
  const { run, policy, agentSlug, subjectName, context, allowed } = input;
  const pack = policy.pack_id || INVESTIGATION_DEFAULT_PACK;
  return {
    schema: INVESTIGATION_START_SCHEMA,
    pack,
    pack_options: { [pack]: policy.pack_options ?? {} },
    agent_slug: agentSlug,
    subject: { opencti_id: run.subject_id, entity_type: run.subject_type, name: subjectName },
    run: {
      id: run.internal_id,
      draft_id: run.draft_id ?? null,
      workspace_id: run.workspace_id ?? null,
      trigger: ENGINE_TRIGGERS[run.run_trigger] ?? 'manual',
    },
    budget: {
      max_iterations: Math.max(0, run.budget.max_iterations - run.budget.used_iterations),
      max_minutes: Math.max(1, Math.floor(input.remainingMinutes)),
      max_enrichment_jobs: Math.max(0, input.remainingEnrichmentJobs),
    },
    policy: {
      enrichment_connector_ids: context.connectors.map((connector) => connector.id),
      allowed_actions: context.allowed_actions,
    },
    context: {
      entities: [context.subject, ...context.entities],
      relationships: context.relationships,
      candidates: context.candidates,
      courses_of_action: context.courses_of_action,
      pirs: context.pir,
    },
    allowed_ids: {
      evidence: Array.from(allowed.evidence),
      candidates: Array.from(allowed.candidates),
      courses_of_action: Array.from(allowed.coursesOfAction),
      entities: Array.from(allowed.entities),
      connectors: Array.from(allowed.connectors),
    },
    continues_investigation_id: input.continuesInvestigationId ?? null,
  };
};

// endregion

// region engine run state

export interface EngineInvestigation {
  id: string;
  status: string;
  revision: number;
  goal_plan: Record<string, unknown> | null;
  steps: Record<string, unknown>[];
  evidence: Record<string, unknown>[] | null;
  conclusion: Record<string, unknown> | null;
  report: string | null;
  report_status: string | null;
  report_sources: Record<string, unknown>[];
  knowledge: Record<string, unknown> | null;
  end_reason_code: string | null;
  iterations_used: number;
  completed_at: string | null;
}

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

const asRecord = (value: unknown): Record<string, unknown> | null => {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
};

const asString = (value: unknown, max = INVESTIGATION_LIMITS.textLength): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  return trimmed.length > max ? `${trimmed.slice(0, max - 3)}...` : trimmed;
};

const asCount = (value: unknown): number => {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? Math.floor(numeric) : 0;
};

/**
 * Keep the goal plan of the investigation engine as an opaque, bounded JSON
 * object: the run renders it, nothing in OpenCTI acts on it.
 */
export const boundGoalPlan = (value: unknown): Record<string, unknown> | null => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  try {
    const serialized = JSON.stringify(value);
    if (serialized.length > INVESTIGATION_LIMITS.goalPlanLength) return null;
    return JSON.parse(serialized) as Record<string, unknown>;
  } catch {
    return null;
  }
};

/** The engine answer of `GET /api/v1/platform/investigations/{id}`, or null when it is not one. */
export const parseEngineInvestigation = (data: unknown): EngineInvestigation | null => {
  const record = asRecord(data);
  const id = asString(record?.id ?? record?.investigation_id, 200);
  if (!record || !id) return null;
  return {
    id,
    status: asString(record.status, 64) ?? 'running',
    revision: Number.isFinite(Number(record.revision)) ? Number(record.revision) : 0,
    goal_plan: boundGoalPlan(record.goal_plan),
    steps: asArray(record.steps).map(asRecord).filter((step): step is Record<string, unknown> => step !== null),
    evidence: Array.isArray(record.evidence) ? record.evidence.map(asRecord).filter((item): item is Record<string, unknown> => item !== null) : null,
    conclusion: asRecord(record.conclusion),
    report: asString(record.report, INVESTIGATION_LIMITS.reportLength),
    report_status: asString(record.report_status, 32),
    report_sources: asArray(record.report_sources).map(asRecord).filter((item): item is Record<string, unknown> => item !== null),
    knowledge: asRecord(record.knowledge),
    end_reason_code: asString(record.end_reason_code, 200),
    iterations_used: asCount(record.iterations_used),
    completed_at: asString(record.completed_at, 64),
  };
};

export type EngineOutcome = 'running' | 'completed' | 'cancelled' | 'failed';

export const engineOutcome = (status: string): EngineOutcome => {
  const normalized = status.toLowerCase();
  if (normalized === 'completed') return 'completed';
  if (normalized === 'cancelled' || normalized === 'canceled') return 'cancelled';
  if (normalized === 'aborted' || normalized === 'failed' || normalized === 'error') return 'failed';
  return 'running';
};

// The report is written after the run, by a model: how long OpenCTI waits for
// it when the engine cannot say whether it is still coming.
export const REPORT_WAIT_MS = 5 * 60 * 1000;

/** A completed engine run whose report is still being written. */
export const isReportPending = (engine: EngineInvestigation, firstSeenCompletedAt: string | null | undefined, now: Date): boolean => {
  if (engine.report) return false;
  if (engine.report_status === 'none' || engine.report_status === 'written') return false;
  const since = new Date(firstSeenCompletedAt ?? engine.completed_at ?? now.toISOString()).getTime();
  const waited = Number.isNaN(since) ? 0 : now.getTime() - since;
  return waited < REPORT_WAIT_MS;
};

const STEP_STATUSES = Object.values(InvestigationStepStatus) as string[];

const boundParams = (value: unknown): Record<string, unknown> | null => {
  const record = asRecord(value);
  if (!record) return null;
  try {
    const serialized = JSON.stringify(record);
    return serialized.length > INVESTIGATION_LIMITS.detailParamsLength ? null : JSON.parse(serialized) as Record<string, unknown>;
  } catch {
    return null;
  }
};

/**
 * The steps of one engine run in the run's shape, replacing the steps the run
 * already mirrored for that engine run and keeping those of earlier ones.
 */
export const mirrorSteps = (current: InvestigationStep[], investigationId: string, engineSteps: Record<string, unknown>[]): InvestigationStep[] => {
  const mirrored = engineSteps.map((step, index): InvestigationStep => {
    const position = Number.isFinite(Number(step.position)) ? Number(step.position) : index;
    const status = String(step.step_status ?? step.status ?? '').toLowerCase();
    return {
      id: asString(step.step_id ?? step.id, 200) ?? `${investigationId}:${position}`,
      investigation_id: investigationId,
      position,
      action: asString(step.action, 200),
      source_name: asString(step.source_name, 500) ?? '-',
      status: (STEP_STATUSES.includes(status) ? status : InvestigationStepStatus.Pending) as InvestigationStepStatus,
      detail_code: asString(step.detail_code, 200),
      detail_params: boundParams(step.detail_params),
      findings_count: asCount(step.findings_count),
      evidence_count: Array.isArray(step.evidence) ? step.evidence.length : asCount(step.evidence_count),
      started_at: asString(step.started_at, 64),
      completed_at: asString(step.completed_at, 64),
    };
  }).sort((a, b) => a.position - b.position);
  const others = current.filter((step) => step.investigation_id !== investigationId);
  const all = [...others, ...mirrored];
  return all.length > INVESTIGATION_LIMITS.steps ? all.slice(all.length - INVESTIGATION_LIMITS.steps) : all;
};

const EVIDENCE_KINDS = Object.values(InvestigationEvidenceKind) as string[];

const isHttpUrl = (value: string | null): value is string => {
  if (!value) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};

const passageId = (investigationId: string, item: { n?: number | null; kind: string; label: string; href?: string | null }) => {
  if (item.n) return `${investigationId}:${item.n}`;
  return `${investigationId}:${createHash('sha256').update(`${item.kind}\u0000${item.label}\u0000${item.href ?? ''}`).digest('hex').slice(0, 16)}`;
};

const toEvidence = (raw: Record<string, unknown>, investigationId: string): InvestigationEvidence | null => {
  const kindValue = String(raw.kind ?? '').toLowerCase();
  const openctiId = asString(raw.opencti_id, 200);
  const fallbackKind = openctiId ? InvestigationEvidenceKind.OpenctiObject : InvestigationEvidenceKind.ToolResult;
  const kind = (EVIDENCE_KINDS.includes(kindValue) ? kindValue : fallbackKind) as InvestigationEvidenceKind;
  const label = asString(raw.label ?? raw.title, 500) ?? openctiId;
  if (!label) return null;
  const n = Number.isInteger(Number(raw.n)) && Number(raw.n) > 0 ? Number(raw.n) : null;
  const href = asString(raw.href ?? raw.url, 2000);
  // An OpenCTI object is linked to the entity itself, never through an address.
  const isObject = kind === InvestigationEvidenceKind.OpenctiObject && openctiId;
  const item: InvestigationEvidence = {
    id: isObject ? openctiId : '',
    investigation_id: investigationId,
    n,
    kind,
    label,
    href: isObject ? null : (isHttpUrl(href) ? href : null),
    quote: asString(raw.quote, INVESTIGATION_LIMITS.quoteLength),
    opencti_id: isObject ? openctiId : null,
    entity_type: asString(raw.entity_type, 100),
    standard_id: null,
    in_draft: false,
    step_id: asString(raw.step_id, 200),
  };
  if (!isObject) item.id = passageId(investigationId, item);
  return item;
};

/**
 * The evidence of one engine run in the shared shape. The engine sends its
 * evidence list; an older answer without it is read from its steps and its
 * report sources. Evidence already on the run keeps its weighting attributes.
 */
export const mirrorEvidence = (current: InvestigationEvidence[], engine: EngineInvestigation): InvestigationEvidence[] => {
  const raw = engine.evidence ?? [
    ...engine.steps.flatMap((step) => asArray(step.evidence).map(asRecord)
      .filter((item): item is Record<string, unknown> => item !== null)
      .map((item) => ({ step_id: step.step_id ?? step.id, ...item }))),
    ...engine.report_sources,
  ];
  const byId = new Map(current.map((item) => [item.id, item]));
  const order = current.map((item) => item.id);
  raw.forEach((rawItem) => {
    const item = toEvidence(rawItem, engine.id);
    if (!item) return;
    const known = byId.get(item.id);
    if (known) {
      // Keep the metadata OpenCTI attached. Every engine run numbers its
      // citations from 1: evidence a continuation cites again takes that
      // run's number and step, never the number an earlier run gave it.
      const sameRun = known.investigation_id === engine.id;
      byId.set(item.id, {
        ...known,
        n: item.n ?? (sameRun ? known.n : null),
        quote: known.quote ?? item.quote,
        investigation_id: engine.id,
        step_id: sameRun ? (known.step_id ?? item.step_id) : (item.step_id ?? known.step_id),
      });
      return;
    }
    byId.set(item.id, item);
    order.push(item.id);
  });
  return order.map((id) => byId.get(id) as InvestigationEvidence).slice(0, INVESTIGATION_LIMITS.evidence);
};

/** The sources the report cites, with addresses that can be followed only. */
export const mirrorReportSources = (engine: EngineInvestigation): InvestigationReportSource[] => {
  return engine.report_sources.map((source): InvestigationReportSource | null => {
    const n = Number(source.n);
    const label = asString(source.label ?? source.title, 500);
    if (!Number.isInteger(n) || n <= 0 || !label) return null;
    const href = asString(source.href ?? source.url, 2000);
    return { n, label, href: isHttpUrl(href) ? href : null };
  }).filter((source): source is InvestigationReportSource => source !== null).slice(0, INVESTIGATION_LIMITS.reportSources);
};

// endregion

// region conclusion

const truncate = (value: unknown, max = INVESTIGATION_LIMITS.textLength): string | null => asString(value, max);

const enumValue = <T extends string>(values: T[], value: unknown, fallback: T): T => {
  if (typeof value !== 'string') return fallback;
  const normalized = value.trim().toLowerCase();
  const match = values.find((v) => v.toLowerCase() === normalized);
  return match ?? fallback;
};

// Category names of the shared conclusion schema, on the ACH categories.
const CATEGORY_ALIASES: Record<string, string> = {
  infrastructure: 'infrastructure_overlap',
  infrastructure_overlap: 'infrastructure_overlap',
  tooling: 'tooling',
  tools: 'tooling',
  malware: 'tooling',
  ttp: 'ttp_overlap',
  ttps: 'ttp_overlap',
  ttp_overlap: 'ttp_overlap',
  victimology: 'victimology',
  targeting: 'victimology',
  temporal: 'temporal',
  timing: 'temporal',
  source_reliability: 'source_reliability',
  reliability: 'source_reliability',
  language: 'language_timezone',
  timezone: 'language_timezone',
  language_timezone: 'language_timezone',
};

const RECOMMENDATION_KIND_ALIASES: Record<string, InvestigationRecommendationActionKind> = {
  create_task: InvestigationRecommendationActionKind.Task,
  task: InvestigationRecommendationActionKind.Task,
  enrich: InvestigationRecommendationActionKind.Task,
  apply_course_of_action: InvestigationRecommendationActionKind.CourseOfAction,
  course_of_action: InvestigationRecommendationActionKind.CourseOfAction,
  escalate: InvestigationRecommendationActionKind.SeverityChange,
  severity_change: InvestigationRecommendationActionKind.SeverityChange,
  notify: InvestigationRecommendationActionKind.Notification,
  notification: InvestigationRecommendationActionKind.Notification,
  share: InvestigationRecommendationActionKind.Sharing,
  sharing: InvestigationRecommendationActionKind.Sharing,
  close_case: InvestigationRecommendationActionKind.CaseClosure,
  case_closure: InvestigationRecommendationActionKind.CaseClosure,
  other: InvestigationRecommendationActionKind.Other,
};

const PRIORITY_ALIASES: Record<string, InvestigationRecommendationPriority> = {
  critical: InvestigationRecommendationPriority.P1,
  p1: InvestigationRecommendationPriority.P1,
  high: InvestigationRecommendationPriority.P2,
  p2: InvestigationRecommendationPriority.P2,
  medium: InvestigationRecommendationPriority.P3,
  p3: InvestigationRecommendationPriority.P3,
  low: InvestigationRecommendationPriority.P4,
  p4: InvestigationRecommendationPriority.P4,
};

// Recommendation kinds that act on the case or reach people outside the
// platform: always behind a human approval, whatever the engine says.
export const SENSITIVE_RECOMMENDATION_KINDS: InvestigationRecommendationActionKind[] = [
  InvestigationRecommendationActionKind.SeverityChange,
  InvestigationRecommendationActionKind.Sharing,
  InvestigationRecommendationActionKind.Notification,
  InvestigationRecommendationActionKind.CaseClosure,
];

export const isSensitiveRecommendationKind = (kind: InvestigationRecommendationActionKind) => SENSITIVE_RECOMMENDATION_KINDS.includes(kind);

const SEVERITY_VALUES = ['low', 'medium', 'high', 'critical'];

const resolveAlias = (allowed: AllowedIds, value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  return allowed.aliases.get(value.trim()) ?? null;
};

/**
 * Resolve an evidence reference of the conclusion: a citation number of the
 * engine run (`cite:3`, `[3]` or `3`), or an OpenCTI id (internal or standard)
 * of its evidence. Every engine run numbers its citations from 1: a number
 * only names evidence of that run, earlier evidence is cited by its id.
 */
const resolveEvidenceRef = (ref: unknown, allowed: AllowedIds, evidence: InvestigationEvidence[], investigationId: string): string | null => {
  const value = typeof ref === 'number' ? String(ref) : (typeof ref === 'string' ? ref.trim().replace(/^cite:\s*/i, '').replace(/^\[|\]$/g, '') : '');
  if (!value) return null;
  if (/^\d+$/.test(value)) {
    const cited = evidence.find((item) => item.n === Number(value) && item.investigation_id === investigationId);
    return cited ? cited.id : null;
  }
  return resolveAlias(allowed, value);
};

export const groundHypotheses = (
  raw: unknown[],
  allowed: AllowedIds,
  candidateInfo: CandidateInfo,
  evidence: InvestigationEvidence[],
  investigationId: string,
): { hypotheses: AchHypothesisInput[]; dropped: number } => {
  const seen = new Set<string>();
  let dropped = 0;
  const hypotheses: AchHypothesisInput[] = [];
  raw.forEach((rawHypothesis) => {
    const hypothesis = asRecord(rawHypothesis);
    const candidateId = resolveAlias(allowed, hypothesis?.candidate_id);
    if (!hypothesis || !candidateId || !allowed.candidates.has(candidateId) || seen.has(candidateId) || hypotheses.length >= INVESTIGATION_LIMITS.hypotheses) {
      dropped += 1;
      return;
    }
    seen.add(candidateId);
    const seenEvidence = new Set<string>();
    const cells: AchCellInput[] = [];
    asArray(hypothesis.evidence).forEach((rawCell) => {
      const cell = asRecord(rawCell);
      const evidenceId = resolveEvidenceRef(cell?.ref ?? cell?.evidence_id, allowed, evidence, investigationId);
      const category = CATEGORY_ALIASES[String(cell?.category ?? '').trim().toLowerCase()];
      if (!cell || !evidenceId || !allowed.evidence.has(evidenceId) || !isEvidenceCategory(category)
        || seenEvidence.has(evidenceId) || cells.length >= INVESTIGATION_LIMITS.evidencePerHypothesis) {
        dropped += 1;
        return;
      }
      seenEvidence.add(evidenceId);
      // The model's own weight is ignored: OpenCTI weights the evidence.
      cells.push({ evidence_id: evidenceId, category, consistency: clampConsistency(cell.consistency), rationale: truncate(cell.rationale) });
    });
    const info = candidateInfo.get(candidateId);
    hypotheses.push({
      candidate_id: candidateId,
      candidate_standard_id: info?.standard_id ?? null,
      candidate_name: info?.name ?? truncate(hypothesis.candidate_name, 500),
      candidate_type: info?.entity_type ?? truncate(hypothesis.candidate_type, 100),
      rationale: truncate(hypothesis.rationale, 4000),
      evidence: cells,
    });
  });
  return { hypotheses, dropped };
};

export const groundRecommendations = (raw: unknown[], allowed: AllowedIds): { recommendations: InvestigationRecommendation[]; dropped: number } => {
  const seen = new Set<string>();
  let dropped = 0;
  const recommendations: InvestigationRecommendation[] = [];
  raw.forEach((rawRecommendation, index) => {
    const recommendation = asRecord(rawRecommendation);
    const text = truncate(recommendation?.text);
    if (!recommendation || !text || recommendations.length >= INVESTIGATION_LIMITS.recommendations) {
      dropped += 1;
      return;
    }
    let id = truncate(recommendation.id, 64) ?? `r${index + 1}`;
    if (seen.has(id)) id = `r${index + 1}`;
    if (seen.has(id)) {
      dropped += 1;
      return;
    }
    seen.add(id);
    const courseOfActionId = resolveAlias(allowed, recommendation.course_of_action_id);
    const groundedCoa = courseOfActionId && allowed.coursesOfAction.has(courseOfActionId) ? courseOfActionId : null;
    if (recommendation.course_of_action_id && !groundedCoa) {
      dropped += 1;
    }
    const rawKind = String(recommendation.kind ?? recommendation.action_kind ?? '').trim().toLowerCase();
    let actionKind = RECOMMENDATION_KIND_ALIASES[rawKind] ?? InvestigationRecommendationActionKind.Other;
    // A course of action that does not exist cannot be applied.
    if (actionKind === InvestigationRecommendationActionKind.CourseOfAction && !groundedCoa) {
      actionKind = InvestigationRecommendationActionKind.Task;
    }
    const severity = actionKind === InvestigationRecommendationActionKind.SeverityChange ? enumValue(SEVERITY_VALUES, recommendation.severity, '') : '';
    const escalation = rawKind === 'escalate';
    if (actionKind === InvestigationRecommendationActionKind.SeverityChange && !severity) {
      // A severity change without a valid target severity becomes a plain task.
      actionKind = InvestigationRecommendationActionKind.Task;
    }
    const approvalRequired = isSensitiveRecommendationKind(actionKind) || escalation || recommendation.approval_required === true;
    const priorityKey = String(recommendation.priority ?? '').trim().toLowerCase();
    recommendations.push({
      id,
      course_of_action_id: groundedCoa,
      text,
      priority: PRIORITY_ALIASES[priorityKey] ?? InvestigationRecommendationPriority.P3,
      rationale: truncate(recommendation.rationale),
      action_kind: actionKind,
      severity: severity || null,
      approval_required: approvalRequired,
      status: approvalRequired ? InvestigationRecommendationStatus.AwaitingApproval : InvestigationRecommendationStatus.Proposed,
      task_id: null,
    });
  });
  return { recommendations, dropped };
};

export interface GroundedConclusion {
  summary: string | null;
  hypotheses: AchHypothesisInput[];
  recommendations: InvestigationRecommendation[];
  dropped: number;
}

/** The engine conclusion (shared `investigation_conclusion` schema), held to what the run may cite. */
export const groundConclusion = (
  conclusion: Record<string, unknown> | null,
  allowed: AllowedIds,
  candidateInfo: CandidateInfo,
  evidence: InvestigationEvidence[],
  investigationId: string,
): GroundedConclusion => {
  if (!conclusion) return { summary: null, hypotheses: [], recommendations: [], dropped: 0 };
  const { hypotheses, dropped: droppedHypotheses } = groundHypotheses(asArray(conclusion.hypotheses), allowed, candidateInfo, evidence, investigationId);
  const { recommendations, dropped: droppedRecommendations } = groundRecommendations(asArray(conclusion.recommendations), allowed);
  return {
    summary: truncate(conclusion.summary, INVESTIGATION_LIMITS.summaryLength),
    hypotheses,
    recommendations,
    dropped: droppedHypotheses + droppedRecommendations,
  };
};

// endregion

// region knowledge list

export interface EngineKnowledge {
  observables: Array<{ type: 'Domain-Name' | 'IPv4-Addr' | 'IPv6-Addr' | 'Url'; value: string }>;
  relationships: Array<{ from: string; to: string; type: string; description: string | null }>;
  notes: Array<{ value: string; content: string }>;
}

const KNOWLEDGE_OBSERVABLE_TYPES = ['Domain-Name', 'IPv4-Addr', 'IPv6-Addr', 'Url'];
const KNOWLEDGE_RELATIONSHIP_TYPES = ['resolves-to', 'related-to'];

const URL_PARTS = /^([a-z][a-z0-9+.-]*:\/\/)([^/?#]*)(.*)$/i;

/**
 * An observable value as written to the draft: addresses and domain names
 * compare without case; a URL keeps the case of its path and query, which
 * carry meaning, and only its scheme and host are lowercased.
 */
export const canonicalObservableValue = (type: string, value: string): string => {
  if (type !== 'Url') return value.toLowerCase();
  const parts = URL_PARTS.exec(value);
  return parts ? `${parts[1].toLowerCase()}${parts[2].toLowerCase()}${parts[3]}` : value;
};

/** The deterministic knowledge list of the engine (`build_knowledge`), bounded and typed. */
export const parseEngineKnowledge = (knowledge: Record<string, unknown> | null): EngineKnowledge => {
  const observables = asArray(knowledge?.observables).map(asRecord).map((item) => {
    const type = asString(item?.type, 50);
    const raw = asString(item?.value, 2000);
    return type && raw && KNOWLEDGE_OBSERVABLE_TYPES.includes(type)
      ? { type: type as EngineKnowledge['observables'][number]['type'], value: canonicalObservableValue(type, raw) }
      : null;
  }).filter((item): item is EngineKnowledge['observables'][number] => item !== null).slice(0, INVESTIGATION_LIMITS.knowledgeObservables);
  // Relationships and notes name observables as the engine wrote them: matched without case.
  const valueOf = new Map(observables.map((item) => [item.value.toLowerCase(), item.value]));
  const known = (value: string | null) => (value ? valueOf.get(value.toLowerCase()) ?? null : null);
  const relationships = asArray(knowledge?.relationships).map((raw) => {
    const item: Record<string, unknown> | null = Array.isArray(raw) ? { from: raw[0], to: raw[1], type: raw[2], description: raw[3] } : asRecord(raw);
    const from = known(asString(item?.from ?? item?.from_value, 2000));
    const to = known(asString(item?.to ?? item?.to_value, 2000));
    const type = asString(item?.type ?? item?.relationship_type, 50);
    if (!from || !to || !type || !KNOWLEDGE_RELATIONSHIP_TYPES.includes(type)) return null;
    return { from, to, type, description: truncate(item?.description) };
  }).filter((item): item is EngineKnowledge['relationships'][number] => item !== null).slice(0, INVESTIGATION_LIMITS.knowledgeRelationships);
  const notes = asArray(knowledge?.notes).map((raw) => {
    const item: Record<string, unknown> | null = Array.isArray(raw) ? { value: raw[0], content: raw[1] } : asRecord(raw);
    const value = known(asString(item?.value ?? item?.observable, 2000));
    const content = truncate(item?.content, INVESTIGATION_LIMITS.summaryLength);
    return value && content ? { value, content } : null;
  }).filter((item): item is EngineKnowledge['notes'][number] => item !== null).slice(0, INVESTIGATION_LIMITS.knowledgeNotes);
  return { observables, relationships, notes };
};

// endregion

/**
 * Candidate threats the conclusion of the engine names, by internal or
 * standard id: its summary and its hypotheses may quote them whether or not
 * they are cited as evidence.
 */
/** The courses of action the recommendations of a conclusion name: their text may quote them. */
export const conclusionCourseOfActionIds = (conclusion: Record<string, unknown> | null | undefined): string[] => {
  const recommendations = conclusion?.recommendations;
  if (!Array.isArray(recommendations)) return [];
  return Array.from(new Set(recommendations
    .map((recommendation) => (recommendation && typeof recommendation === 'object' ? (recommendation as Record<string, unknown>).course_of_action_id : null))
    .filter((id): id is string => typeof id === 'string' && id.length > 0)))
    .slice(0, INVESTIGATION_LIMITS.coursesOfAction);
};

export const conclusionCandidateIds = (conclusion: Record<string, unknown> | null | undefined): string[] => {
  const hypotheses = conclusion?.hypotheses;
  if (!Array.isArray(hypotheses)) return [];
  return Array.from(new Set(hypotheses
    .map((hypothesis) => (hypothesis && typeof hypothesis === 'object' ? (hypothesis as Record<string, unknown>).candidate_id : null))
    .filter((id): id is string => typeof id === 'string' && id.length > 0)))
    .slice(0, INVESTIGATION_LIMITS.candidates);
};

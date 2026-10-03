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

// Contract with the XTM One Case Autopilot agent: the request OpenCTI sends
// and the grounding of the answer. Pure functions only: the agent is never
// trusted with an id it was not given, an enum it made up or an unbounded list.

import {
  InvestigationPlanStepKind,
  InvestigationPlanStepStatus,
  InvestigationRecommendationActionKind,
  InvestigationRecommendationPriority,
  InvestigationRecommendationStatus,
  InvestigationRunPhase,
} from '../../generated/graphql';
import { clampConsistency, isEvidenceCategory, type AchCellInput, type AchHypothesisInput } from './investigationRun-ach';
import {
  INVESTIGATION_LIMITS,
  INVESTIGATION_REQUEST_SCHEMA,
  type BasicStoreEntityInvestigationRun,
  type InvestigationPlanStep,
  type InvestigationRecommendation,
} from './investigationRun-types';

export type AgentPhase = 'plan' | 'iterate' | 'conclude';

export interface AgentContextEntity {
  id: string;
  standard_id?: string | null;
  entity_type: string;
  name?: string | null;
  description?: string | null;
  created?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  confidence?: number | null;
  author?: string | null;
  author_reliability?: string | null;
}

export interface AgentContextRelationship {
  id: string;
  standard_id?: string | null;
  relationship_type: string;
  from_id: string;
  to_id: string;
  first_seen?: string | null;
  last_seen?: string | null;
  confidence?: number | null;
}

export interface AgentContextCandidate {
  id: string;
  standard_id?: string | null;
  entity_type: string;
  name: string;
  aliases?: string[];
}

export interface AgentContextCourseOfAction {
  id: string;
  standard_id?: string | null;
  name: string;
  x_mitre_id?: string | null;
}

export interface AgentEnrichmentConnector {
  id: string;
  name: string;
  scope: string[];
  requires_approval: boolean;
}

export interface InvestigationAgentContext {
  subject: AgentContextEntity;
  entities: AgentContextEntity[];
  relationships: AgentContextRelationship[];
  candidates: AgentContextCandidate[];
  courses_of_action: AgentContextCourseOfAction[];
  pir: Array<{ id: string; name: string; score: number }>;
  connectors: AgentEnrichmentConnector[];
  allowed_actions: string[];
}

export interface AgentDelta {
  new_entity_ids: string[];
  new_relationship_ids: string[];
  enrichments: Array<{ entity_id: string; connector_id: string; status: string; new_object_ids: string[] }>;
}

export interface AllowedIds {
  evidence: Set<string>;
  candidates: Set<string>;
  coursesOfAction: Set<string>;
  entities: Set<string>;
  connectors: Set<string>;
  // Standard ids (and any other alias) the agent may cite instead of internal ids.
  aliases: Map<string, string>;
}

export interface GroundedEnrichmentRequest {
  entity_id: string;
  connector_id: string;
  reason: string | null;
}

export interface GroundedAgentResponse {
  plan: InvestigationPlanStep[];
  enrichment_requests: GroundedEnrichmentRequest[];
  hypotheses: AchHypothesisInput[];
  recommendations: InvestigationRecommendation[];
  summary: string | null;
  // The investigation engine's own goal plan, kept as it answered it (bounded).
  goal_plan: Record<string, unknown> | null;
  done: boolean;
  dropped: number;
}

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

// Recommendation kinds that act on the case or reach people outside the
// platform: always behind a human approval, whatever the agent says.
export const SENSITIVE_RECOMMENDATION_KINDS: InvestigationRecommendationActionKind[] = [
  InvestigationRecommendationActionKind.SeverityChange,
  InvestigationRecommendationActionKind.Sharing,
  InvestigationRecommendationActionKind.Notification,
  InvestigationRecommendationActionKind.CaseClosure,
];

const SEVERITY_VALUES = ['low', 'medium', 'high', 'critical'];

const truncate = (value: unknown, max = INVESTIGATION_LIMITS.textLength): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  return trimmed.length > max ? `${trimmed.slice(0, max - 3)}...` : trimmed;
};

const enumValue = <T extends string>(values: T[], value: unknown, fallback: T): T => {
  if (typeof value !== 'string') return fallback;
  const normalized = value.trim().toLowerCase();
  const match = values.find((v) => v.toLowerCase() === normalized);
  return match ?? fallback;
};

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

const asRecord = (value: unknown): Record<string, unknown> | null => {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
};

export const agentPhaseFor = (phase: InvestigationRunPhase): AgentPhase => {
  if (phase === InvestigationRunPhase.Planning) return 'plan';
  if (phase === InvestigationRunPhase.Concluding) return 'conclude';
  return 'iterate';
};

export const buildAllowedIds = (context: InvestigationAgentContext, extraEvidence: Array<{ id: string; standard_id?: string | null }> = []): AllowedIds => {
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

export const buildAgentRequest = (
  run: BasicStoreEntityInvestigationRun,
  phase: AgentPhase,
  context: InvestigationAgentContext,
  delta: AgentDelta,
  allowed: AllowedIds,
  remainingMinutes: number,
): string => {
  const request = {
    schema: INVESTIGATION_REQUEST_SCHEMA,
    phase,
    run: {
      id: run.internal_id,
      iteration: run.iteration,
      trigger: run.run_trigger,
      pack_id: run.pack_id ?? null,
      subject: context.subject,
      case_id: run.case_id ?? null,
      draft_id: run.draft_id ?? null,
      workspace_id: run.workspace_id ?? null,
    },
    budget: {
      max_tool_calls: run.budget.max_tool_calls,
      used_tool_calls: run.budget.used_tool_calls,
      max_enrichment_jobs: run.budget.max_enrichment_jobs,
      used_enrichment_jobs: run.budget.used_enrichment_jobs,
      remaining_minutes: Math.max(0, Math.round(remainingMinutes * 10) / 10),
    },
    policy: {
      allowed_actions: context.allowed_actions,
      enrichment_connectors: context.connectors,
    },
    context: {
      entities: context.entities,
      relationships: context.relationships,
      candidates: context.candidates,
      courses_of_action: context.courses_of_action,
      pir: context.pir,
    },
    plan: run.plan,
    ledger: run.steps.slice(-50).map((step) => ({
      id: step.id,
      tool: step.tool,
      description: step.description,
      status: step.status,
      output_ref: step.output_ref ?? null,
    })),
    delta,
    hypotheses: run.hypotheses.map((hypothesis) => ({
      candidate_id: hypothesis.candidate_id,
      candidate_name: hypothesis.candidate_name,
      candidate_type: hypothesis.candidate_type,
      rationale: hypothesis.rationale,
      evidence: hypothesis.evidence.map((cell) => ({
        evidence_id: cell.evidence_id,
        category: cell.category,
        consistency: cell.consistency,
        rationale: cell.rationale,
      })),
      score: hypothesis.score,
      probability: hypothesis.probability,
      confidence_label: hypothesis.confidence_label,
    })),
    allowed_ids: {
      evidence: Array.from(allowed.evidence),
      candidates: Array.from(allowed.candidates),
      courses_of_action: Array.from(allowed.coursesOfAction),
      entities: Array.from(allowed.entities),
      connectors: Array.from(allowed.connectors),
    },
  };
  return JSON.stringify(request);
};

/**
 * Extract the JSON object of an agent answer. The agent runs with a strict
 * JSON output schema, but a code fence or a sentence around the object must
 * not fail the whole run.
 */
export const parseAgentResponse = (raw: string | null | undefined): Record<string, unknown> | null => {
  if (!raw) return null;
  const text = raw.trim();
  const candidates: string[] = [text];
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fenced) candidates.push(fenced[1].trim());
  const firstBrace = text.indexOf('{');
  const lastBrace = text.lastIndexOf('}');
  if (firstBrace >= 0 && lastBrace > firstBrace) candidates.push(text.slice(firstBrace, lastBrace + 1));
  for (let index = 0; index < candidates.length; index += 1) {
    try {
      const parsed = JSON.parse(candidates[index]);
      const record = asRecord(parsed);
      if (record) return record;
    } catch {
      // Try the next candidate.
    }
  }
  return null;
};

const resolveAlias = (allowed: AllowedIds, value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  return allowed.aliases.get(value.trim()) ?? null;
};

const groundPlan = (rawPlan: unknown[]): { plan: InvestigationPlanStep[]; dropped: number } => {
  const seen = new Set<string>();
  let dropped = 0;
  const plan: InvestigationPlanStep[] = [];
  rawPlan.forEach((rawStep, index) => {
    const step = asRecord(rawStep);
    const description = truncate(step?.description);
    if (!step || !description || plan.length >= INVESTIGATION_LIMITS.planSteps) {
      dropped += 1;
      return;
    }
    let id = truncate(step.id, 64) ?? `s${index + 1}`;
    if (seen.has(id)) id = `s${index + 1}`;
    if (seen.has(id)) {
      dropped += 1;
      return;
    }
    seen.add(id);
    plan.push({
      id,
      kind: enumValue(Object.values(InvestigationPlanStepKind), step.kind, InvestigationPlanStepKind.Pivot),
      description,
      status: enumValue(
        [InvestigationPlanStepStatus.Pending, InvestigationPlanStepStatus.Done, InvestigationPlanStepStatus.Skipped],
        step.status,
        InvestigationPlanStepStatus.Pending,
      ),
      approval_required: step.approval_required === true,
    });
  });
  return { plan, dropped };
};

const groundEnrichmentRequests = (raw: unknown[], allowed: AllowedIds): { requests: GroundedEnrichmentRequest[]; dropped: number } => {
  const seen = new Set<string>();
  let dropped = 0;
  const requests: GroundedEnrichmentRequest[] = [];
  raw.forEach((rawRequest) => {
    const request = asRecord(rawRequest);
    const entityId = resolveAlias(allowed, request?.entity_id);
    const connectorId = typeof request?.connector_id === 'string' && allowed.connectors.has(request.connector_id) ? request.connector_id : null;
    if (!entityId || !allowed.entities.has(entityId) || !connectorId || requests.length >= INVESTIGATION_LIMITS.enrichmentRequestsPerCall) {
      dropped += 1;
      return;
    }
    const key = `${entityId}::${connectorId}`;
    if (seen.has(key)) {
      dropped += 1;
      return;
    }
    seen.add(key);
    requests.push({ entity_id: entityId, connector_id: connectorId, reason: truncate(request?.reason) });
  });
  return { requests, dropped };
};

export const groundHypotheses = (
  raw: unknown[],
  allowed: AllowedIds,
  candidateInfo: Map<string, { name?: string | null; entity_type?: string | null; standard_id?: string | null }>,
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
    const evidence: AchCellInput[] = [];
    asArray(hypothesis.evidence).forEach((rawCell) => {
      const cell = asRecord(rawCell);
      const evidenceId = resolveAlias(allowed, cell?.evidence_id);
      if (!cell || !evidenceId || !allowed.evidence.has(evidenceId) || !isEvidenceCategory(cell.category)
        || seenEvidence.has(evidenceId) || evidence.length >= INVESTIGATION_LIMITS.evidencePerHypothesis) {
        dropped += 1;
        return;
      }
      seenEvidence.add(evidenceId);
      evidence.push({
        evidence_id: evidenceId,
        category: cell.category,
        consistency: clampConsistency(cell.consistency),
        rationale: truncate(cell.rationale),
      });
    });
    const info = candidateInfo.get(candidateId);
    hypotheses.push({
      candidate_id: candidateId,
      candidate_standard_id: info?.standard_id ?? null,
      candidate_name: info?.name ?? truncate(hypothesis.candidate_name, 500),
      candidate_type: info?.entity_type ?? truncate(hypothesis.candidate_type, 100),
      rationale: truncate(hypothesis.rationale, 4000),
      evidence,
    });
  });
  return { hypotheses, dropped };
};

export const isSensitiveRecommendationKind = (kind: InvestigationRecommendationActionKind) => SENSITIVE_RECOMMENDATION_KINDS.includes(kind);

const groundRecommendations = (raw: unknown[], allowed: AllowedIds): { recommendations: InvestigationRecommendation[]; dropped: number } => {
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
    let actionKind = enumValue(Object.values(InvestigationRecommendationActionKind), recommendation.action_kind, InvestigationRecommendationActionKind.Other);
    // A course of action that does not exist cannot be applied.
    if (actionKind === InvestigationRecommendationActionKind.CourseOfAction && !groundedCoa) {
      actionKind = InvestigationRecommendationActionKind.Task;
    }
    const severity = actionKind === InvestigationRecommendationActionKind.SeverityChange
      ? enumValue(SEVERITY_VALUES, recommendation.severity, '')
      : '';
    if (actionKind === InvestigationRecommendationActionKind.SeverityChange && !severity) {
      // A severity change without a valid target severity becomes a plain task.
      actionKind = InvestigationRecommendationActionKind.Task;
    }
    const approvalRequired = isSensitiveRecommendationKind(actionKind) || recommendation.approval_required === true;
    recommendations.push({
      id,
      course_of_action_id: groundedCoa,
      text,
      priority: enumValue(Object.values(InvestigationRecommendationPriority), recommendation.priority, InvestigationRecommendationPriority.P3),
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

export const groundAgentResponse = (
  response: Record<string, unknown>,
  allowed: AllowedIds,
  candidateInfo: Map<string, { name?: string | null; entity_type?: string | null; standard_id?: string | null }>,
): GroundedAgentResponse => {
  const { plan, dropped: droppedPlan } = groundPlan(asArray(response.plan));
  const { requests, dropped: droppedRequests } = groundEnrichmentRequests(asArray(response.enrichment_requests), allowed);
  const { hypotheses, dropped: droppedHypotheses } = groundHypotheses(asArray(response.hypotheses), allowed, candidateInfo);
  const { recommendations, dropped: droppedRecommendations } = groundRecommendations(asArray(response.recommendations), allowed);
  return {
    plan,
    enrichment_requests: requests,
    hypotheses,
    recommendations,
    summary: truncate(response.summary, INVESTIGATION_LIMITS.summaryLength),
    goal_plan: boundGoalPlan(response.goal_plan),
    done: response.done === true,
    dropped: droppedPlan + droppedRequests + droppedHypotheses + droppedRecommendations,
  };
};

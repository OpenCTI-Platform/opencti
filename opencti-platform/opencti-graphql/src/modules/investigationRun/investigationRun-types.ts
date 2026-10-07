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

import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';
import {
  InvestigationApprovalKind,
  InvestigationApprovalStatus,
  InvestigationAutonomousAction,
  InvestigationConfidenceLabel,
  InvestigationEnrichmentRequestStatus,
  InvestigationEnrichmentWaveStatus,
  InvestigationEvidenceCategory,
  InvestigationEvidenceKind,
  InvestigationFeedbackDecision,
  InvestigationFeedbackItemType,
  InvestigationRecommendationActionKind,
  InvestigationRecommendationPriority,
  InvestigationRecommendationStatus,
  InvestigationRunPhase,
  InvestigationRunStatus,
  InvestigationRunTrigger,
  InvestigationStepStatus,
} from '../../generated/graphql';

export const ENTITY_TYPE_INVESTIGATION_RUN = 'InvestigationRun';
export const ENTITY_TYPE_INVESTIGATION_POLICY = 'InvestigationPolicy';
// Internal types that exist only under the Enterprise Edition: their own
// queries check it, and so does every generic read of them.
export const INVESTIGATION_ENTERPRISE_EDITION_TYPES = [ENTITY_TYPE_INVESTIGATION_RUN, ENTITY_TYPE_INVESTIGATION_POLICY];

// The XTM One intent the investigation engine answers OpenCTI case runs on
// (declared in xtm-one.ts), and the engine contract (XTM One dev-docs/investigations.md).
export const INVESTIGATION_INTENT = 'cti.autonomous_investigation';
export const INVESTIGATION_DEFAULT_AGENT_SLUG = 'deep-investigation-agent';
export const INVESTIGATION_DEFAULT_PACK = 'opencti-case-investigation';
export const INVESTIGATION_START_SCHEMA = 'opencti.investigation.start/v1';

export const INVESTIGATION_RUN_STATUSES = Object.values(InvestigationRunStatus);
export const INVESTIGATION_RUN_TRIGGERS = Object.values(InvestigationRunTrigger);
export const INVESTIGATION_RUN_PHASES = Object.values(InvestigationRunPhase);
export const INVESTIGATION_AUTONOMOUS_ACTIONS = Object.values(InvestigationAutonomousAction);

// A run in one of these statuses is still owned by the manager: a second run
// on the same subject is refused (dedupe) and the manager keeps ticking it.
export const ACTIVE_RUN_STATUSES: InvestigationRunStatus[] = [
  InvestigationRunStatus.Planned,
  InvestigationRunStatus.Running,
  InvestigationRunStatus.AwaitingApproval,
];
export const TERMINAL_RUN_STATUSES: InvestigationRunStatus[] = [
  InvestigationRunStatus.Completed,
  InvestigationRunStatus.Failed,
  InvestigationRunStatus.Cancelled,
];

// Subject types an investigation can start from. Observables are matched on
// the abstract type at validation time.
export const INVESTIGATION_CASE_SUBJECT_TYPES = ['Case-Incident', 'Case-Rfi', 'Case-Rft'];
// Entities with an Autopilot tab of their own; indicators and observables are
// investigated inside a case.
export const INVESTIGATION_TAB_SUBJECT_TYPES = [...INVESTIGATION_CASE_SUBJECT_TYPES, 'Incident'];
export const INVESTIGATION_SUBJECT_TYPES = [...INVESTIGATION_TAB_SUBJECT_TYPES, 'Indicator'];

// Why an investigation could not run on the engine (end_reason_code of the run).
export const ENGINE_NOT_CONFIGURED = 'engine_not_configured';
export const ENGINE_DISABLED = 'engine_disabled';
export const ENGINE_UNAVAILABLE = 'engine_unavailable';
export const ENGINE_NO_AGENT = 'engine_no_agent';
export const ENGINE_UNREACHABLE = 'engine_unreachable';

// Why a run stopped at an access boundary, with what it derived withheld.
export const MEMBER_RESTRICTED_CODE = 'member_restricted';
export const SUBJECT_INACCESSIBLE_CODE = 'subject_inaccessible';
export const CARRY_BOUNDARY_CODES = [MEMBER_RESTRICTED_CODE, SUBJECT_INACCESSIBLE_CODE];
// Served, never stored: what a run found is withheld from a reader who can no
// longer read one of its sources.
export const SOURCE_INACCESSIBLE_CODE = 'source_inaccessible';

// Why a run whose draft was approved did not complete: the platform reported
// errors writing the approved changes, or did not confirm them in time.
export const DRAFT_VALIDATION_FAILED_CODE = 'draft_validation_failed';
export const DRAFT_VALIDATION_UNCONFIRMED_CODE = 'draft_validation_unconfirmed';

// Engine status of a cancelled run whose engine run XTM One has not confirmed
// stopping yet (asked again by the manager), then given up on.
export const ENGINE_CANCEL_PENDING = 'cancel_pending';
export const ENGINE_CANCEL_FAILED = 'cancel_failed';

// Hard caps applied to every list stored on a run, whatever the policy says,
// so a run document stays bounded.
export const INVESTIGATION_LIMITS = {
  steps: 300,
  hypotheses: 6,
  evidencePerHypothesis: 30,
  recommendations: 10,
  enrichmentRequestsPerCall: 20,
  enrichmentWaves: 100,
  waveDelta: 200,
  evidence: 400,
  timeline: 300,
  contextEntities: 150,
  contextRelationships: 300,
  candidates: 40,
  coursesOfAction: 40,
  // The context of the latest engine runs (continuations included) a run keeps reading.
  contextSources: 1200,
  approvals: 200,
  enrichmentEntities: 300,
  feedback: 500,
  reportSources: 100,
  knowledgeObservables: 120,
  knowledgeRelationships: 200,
  knowledgeNotes: 50,
  textLength: 2000,
  quoteLength: 1000,
  summaryLength: 20000,
  reportLength: 100000,
  goalPlanLength: 65536,
  detailParamsLength: 2000,
  // Consecutive manager ticks the engine may fail to answer before the run fails.
  engineFailures: 30,
  // Consecutive manager ticks a transient platform failure (database, lock, network) may interrupt before the run fails.
  stepFailures: 10,
};

export interface InvestigationStep {
  id: string;
  // The engine run the step belongs to (a continuation adds a new one).
  investigation_id: string;
  position: number;
  action?: string | null;
  source_name: string;
  status: InvestigationStepStatus;
  detail_code?: string | null;
  detail_params?: Record<string, unknown> | null;
  findings_count: number;
  evidence_count: number;
  started_at?: string | null;
  completed_at?: string | null;
}

export interface InvestigationEvidence {
  // The OpenCTI id of an OpenCTI object, else `<investigation id>:<n>` or a
  // stable hash of the cited passage.
  id: string;
  investigation_id?: string | null;
  n?: number | null;
  kind: InvestigationEvidenceKind;
  label: string;
  href?: string | null;
  quote?: string | null;
  opencti_id?: string | null;
  entity_type?: string | null;
  standard_id?: string | null;
  in_draft: boolean;
  // The engine step that found it; null for the context OpenCTI collected itself.
  step_id?: string | null;
  // Attributes the ACH helper reads to weight an OpenCTI object; never shown raw.
  confidence?: number | null;
  author_reliability?: string | null;
  created?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface InvestigationEvidenceCell {
  evidence_id: string;
  evidence_standard_id?: string | null;
  evidence_type?: string | null;
  evidence_name?: string | null;
  category: InvestigationEvidenceCategory;
  consistency: number;
  weight: number;
  diagnosticity: number;
  rationale?: string | null;
}

export interface InvestigationHypothesis {
  candidate_id: string;
  candidate_standard_id?: string | null;
  candidate_name?: string | null;
  candidate_type?: string | null;
  rationale?: string | null;
  evidence: InvestigationEvidenceCell[];
  rank: number;
  score: number;
  inconsistency: number;
  probability: number;
  // Null when no evidence assessed the hypothesis: a confidence is never defaulted.
  confidence: number | null;
  confidence_label: InvestigationConfidenceLabel | null;
  explanation: string;
}

export interface InvestigationTimelineEvent {
  ts: string;
  entity_id: string;
  entity_type: string;
  name?: string | null;
  event: string;
}

export interface InvestigationRecommendation {
  id: string;
  course_of_action_id?: string | null;
  text: string;
  priority: InvestigationRecommendationPriority;
  rationale?: string | null;
  action_kind: InvestigationRecommendationActionKind;
  severity?: string | null;
  approval_required: boolean;
  status: InvestigationRecommendationStatus;
  task_id?: string | null;
}

export interface InvestigationFeedback {
  item_type: InvestigationFeedbackItemType;
  item_ref: string;
  decision: InvestigationFeedbackDecision;
  comment?: string | null;
  user_id: string;
  ts: string;
}

export interface InvestigationBudget {
  max_iterations: number;
  max_enrichment_jobs: number;
  max_minutes: number;
  used_iterations: number;
  used_enrichment_jobs: number;
  used_minutes: number;
  // Iterations used before the current engine run started (continuations).
  iterations_base?: number;
}

export interface InvestigationApproval {
  id: string;
  kind: InvestigationApprovalKind;
  status: InvestigationApprovalStatus;
  description: string;
  reason?: string | null;
  connector_id?: string | null;
  entity_id?: string | null;
  recommendation_id?: string | null;
  created_at: string;
  decided_at?: string | null;
  decided_by?: string | null;
  rejection_reason?: string | null;
}

export interface InvestigationEnrichmentRequest {
  id: string;
  wave_id?: string | null;
  entity_id: string;
  connector_id: string;
  connector_name?: string | null;
  reason?: string | null;
  status: InvestigationEnrichmentRequestStatus;
  requested_by: string;
  work_id?: string | null;
  error?: string | null;
  created_at: string;
  dispatched_at?: string | null;
  completed_at?: string | null;
}

export interface InvestigationDeltaObject {
  id: string;
  standard_id?: string | null;
  entity_type: string;
  representative?: string | null;
  connector_name?: string | null;
  action: 'created' | 'updated';
  // The endpoints of a relationship, sent to the engine with it.
  from_id?: string | null;
  to_id?: string | null;
}

// One call of the engine's enrichment querier: the jobs it asked for, and
// what they brought into the run's Draft once they ended.
export interface InvestigationEnrichmentWave {
  id: string;
  status: InvestigationEnrichmentWaveStatus;
  requested_at: string;
  completed_at?: string | null;
  request_ids: string[];
  delta: InvestigationDeltaObject[];
  delta_computed: boolean;
}

export interface InvestigationReportSource {
  n: number;
  label: string;
  href?: string | null;
}

// Objects the run wrote into its Draft, updated (not duplicated) when a
// continuation concludes again.
export interface InvestigationOutputs {
  note_id?: string | null;
  note_standard_id?: string | null;
  report_id?: string | null;
  report_standard_id?: string | null;
  attributed_candidate_ids: string[];
  // Observables of the engine's knowledge list, by value.
  observable_ids: Record<string, string>;
  // Finding notes of the engine's knowledge list, by a digest of their value and content.
  finding_note_ids?: Record<string, string>;
  // The engine run these outputs were written for, and what could not be written.
  written_for?: string | null;
  write_failures?: string[];
}

export const EMPTY_OUTPUTS: InvestigationOutputs = { attributed_candidate_ids: [], observable_ids: {} };

export interface InvestigationAcceptance {
  hypotheses_accepted: number;
  hypotheses_rejected: number;
  recommendations_accepted: number;
  recommendations_rejected: number;
}

interface InvestigationRunAttributes {
  name: string;
  subject_id: string;
  subject_type: string;
  // Every id the case of the run is known by: its internal id, its standard
  // id (stable across a draft validation) and, after validation, its live
  // internal id. Case pages look runs up by any of them.
  case_id?: string | null;
  case_ids: string[];
  // A new Case-Incident is created in the run Draft for an indicator or an
  // observable investigated without an existing case.
  create_case: boolean;
  // What the engine received as context, cited or not: entities, relationships,
  // candidates, courses of action and PIRs. Empty on runs started before the
  // context was recorded.
  context_ids?: string[];
  workspace_id?: string | null;
  draft_id?: string | null;
  policy_id?: string | null;
  agent_slug?: string | null;
  pack_id?: string | null;
  // The engine runs of this investigation: the latest, every one (continuations)
  // and the revision of the latest the run mirrors.
  xtm_investigation_id?: string | null;
  xtm_investigation_ids: string[];
  xtm_revision: number;
  xtm_status?: string | null;
  xtm_completed_at?: string | null;
  // Set while a continuation waits to start: the engine run it continues.
  continues_investigation_id?: string | null;
  // The time budget made OpenCTI cancel the engine run: its results are kept.
  budget_cancelled: boolean;
  run_trigger: InvestigationRunTrigger;
  run_status: InvestigationRunStatus;
  run_phase: InvestigationRunPhase;
  status_reason?: string | null;
  end_reason_code?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  // Wall-clock time spent running (approval pauses excluded) and the moment
  // the current running slice started, so budgets ignore human think time.
  active_ms: number;
  running_since?: string | null;
  // Enrichment works not finished yet.
  pending_work_ids: string[];
  wave_started_at?: string | null;
  validation_work_id?: string | null;
  engine_failures: number;
  step_failures?: number | null;
  run_as_id: string;
  goal_plan?: Record<string, unknown> | null;
  steps: InvestigationStep[];
  evidence: InvestigationEvidence[];
  hypotheses: InvestigationHypothesis[];
  timeline: InvestigationTimelineEvent[];
  recommendations: InvestigationRecommendation[];
  analyst_feedback: InvestigationFeedback[];
  approvals: InvestigationApproval[];
  enrichment_requests: InvestigationEnrichmentRequest[];
  enrichment_waves: InvestigationEnrichmentWave[];
  budget: InvestigationBudget;
  summary?: string | null;
  report?: string | null;
  report_sources: InvestigationReportSource[];
  outputs: InvestigationOutputs;
}

export interface BasicStoreEntityInvestigationRun extends BasicStoreEntity, InvestigationRunAttributes {}

export interface StoreEntityInvestigationRun extends StoreEntity, InvestigationRunAttributes {}

export interface StixInvestigationRun extends StixInternal {
  name: string;
  subject_id: string;
  run_status: string;
}

// The description comes from the base store entity.
interface InvestigationPolicyAttributes {
  name: string;
  is_default: boolean;
  agent_slug?: string | null;
  pack_id?: string | null;
  // Choices of the pack (`pack_options` of the start body), by option key.
  pack_options?: Record<string, string> | null;
  allowed_actions: InvestigationAutonomousAction[];
  enrichment_connector_ids: string[];
  approval_connector_ids: string[];
  auto_approve_low_risk: boolean;
  auto_approve_min_confidence: number;
  attribution_min_confidence: number;
  max_iterations: number;
  max_enrichment_jobs: number;
  max_minutes: number;
  trigger_on_case_rfi_creation: boolean;
  // Stream position of the Case-Rfi creation hook, persisted like a PIR's.
  last_event_id?: string | null;
  run_as_id?: string | null;
  hypotheses_accepted: number;
  hypotheses_rejected: number;
  recommendations_accepted: number;
  recommendations_rejected: number;
}

export interface BasicStoreEntityInvestigationPolicy extends BasicStoreEntity, InvestigationPolicyAttributes {}

export interface StoreEntityInvestigationPolicy extends StoreEntity, InvestigationPolicyAttributes {}

export interface StixInvestigationPolicy extends StixInternal {
  name: string;
}

// Defaults of a new policy and of the built-in default policy.
export const DEFAULT_POLICY_VALUES = {
  allowed_actions: [
    InvestigationAutonomousAction.Enrichment,
    InvestigationAutonomousAction.CreateCase,
    InvestigationAutonomousAction.AddToCase,
    InvestigationAutonomousAction.CreateNote,
    InvestigationAutonomousAction.CreateRelationship,
  ],
  enrichment_connector_ids: [] as string[],
  approval_connector_ids: [] as string[],
  auto_approve_low_risk: false,
  auto_approve_min_confidence: 80,
  attribution_min_confidence: 55,
  max_iterations: 10,
  max_enrichment_jobs: 20,
  max_minutes: 30,
  trigger_on_case_rfi_creation: false,
};

export const DEFAULT_POLICY_NAME = 'Default investigation policy';

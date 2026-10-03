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
  InvestigationEvidenceCategory,
  InvestigationEvidenceOrigin,
  InvestigationFeedbackDecision,
  InvestigationFeedbackItemType,
  InvestigationLedgerStatus,
  InvestigationPlanStepKind,
  InvestigationPlanStepStatus,
  InvestigationRecommendationActionKind,
  InvestigationRecommendationPriority,
  InvestigationRecommendationStatus,
  InvestigationRunPhase,
  InvestigationRunStatus,
  InvestigationRunTrigger,
} from '../../generated/graphql';

export const ENTITY_TYPE_INVESTIGATION_RUN = 'InvestigationRun';
export const ENTITY_TYPE_INVESTIGATION_POLICY = 'InvestigationPolicy';

// The XTM One intent the Case Autopilot agent is bound to (declared in xtm-one.ts).
export const INVESTIGATION_INTENT = 'cti.autonomous_investigation';
export const INVESTIGATION_DEFAULT_AGENT_SLUG = 'opencti-case-autopilot';
export const INVESTIGATION_REQUEST_SCHEMA = 'opencti.case_autopilot.request/v1';

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
export const INVESTIGATION_SUBJECT_TYPES = [...INVESTIGATION_CASE_SUBJECT_TYPES, 'Incident', 'Indicator'];

// Hard caps applied to every list stored on a run, whatever the policy says,
// so a run document stays bounded.
export const INVESTIGATION_LIMITS = {
  planSteps: 20,
  ledgerEntries: 500,
  hypotheses: 6,
  evidencePerHypothesis: 30,
  recommendations: 10,
  enrichmentRequestsPerCall: 20,
  evidence: 400,
  timeline: 300,
  contextEntities: 150,
  contextRelationships: 300,
  candidates: 40,
  coursesOfAction: 40,
  approvals: 200,
  feedback: 500,
  textLength: 2000,
  summaryLength: 20000,
  agentRetries: 2,
};

export interface InvestigationPlanStep {
  id: string;
  kind: InvestigationPlanStepKind;
  description: string;
  status: InvestigationPlanStepStatus;
  approval_required: boolean;
}

export interface InvestigationLedgerEntry {
  id: string;
  step_id?: string | null;
  iteration: number;
  tool: string;
  description: string;
  input_ref?: string | null;
  output_ref?: string | null;
  status: InvestigationLedgerStatus;
  started_at: string;
  duration_ms: number;
  cost_units: number;
  work_id?: string | null;
  error?: string | null;
}

export interface InvestigationEvidence {
  id: string;
  standard_id?: string | null;
  entity_type: string;
  name?: string | null;
  origin: InvestigationEvidenceOrigin;
  in_draft: boolean;
  // Attributes the ACH helper reads to weight the evidence; never shown raw.
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
  confidence: number;
  confidence_label: InvestigationConfidenceLabel;
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
  max_tool_calls: number;
  max_enrichment_jobs: number;
  max_minutes: number;
  used_tool_calls: number;
  used_enrichment_jobs: number;
  used_minutes: number;
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
  entity_id: string;
  connector_id: string;
  connector_name?: string | null;
  reason?: string | null;
  status: InvestigationEnrichmentRequestStatus;
  requested_by: string;
  iteration: number;
  work_id?: string | null;
  created_at: string;
  completed_at?: string | null;
}

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
  workspace_id?: string | null;
  draft_id?: string | null;
  policy_id?: string | null;
  agent_slug?: string | null;
  run_trigger: InvestigationRunTrigger;
  run_status: InvestigationRunStatus;
  run_phase: InvestigationRunPhase;
  status_reason?: string | null;
  iteration: number;
  started_at?: string | null;
  completed_at?: string | null;
  // Wall-clock time spent running (approval pauses excluded) and the moment
  // the current running slice started, so budgets ignore human think time.
  active_ms: number;
  running_since?: string | null;
  // Works the manager is waiting for during an enrichment wave, and when the wave started.
  pending_work_ids: string[];
  wave_started_at?: string | null;
  validation_work_id?: string | null;
  agent_failures: number;
  run_as_id: string;
  plan: InvestigationPlanStep[];
  steps: InvestigationLedgerEntry[];
  evidence: InvestigationEvidence[];
  hypotheses: InvestigationHypothesis[];
  timeline: InvestigationTimelineEvent[];
  recommendations: InvestigationRecommendation[];
  analyst_feedback: InvestigationFeedback[];
  approvals: InvestigationApproval[];
  enrichment_requests: InvestigationEnrichmentRequest[];
  budget: InvestigationBudget;
  summary?: string | null;
  // What the last enrichment wave brought, sent to the agent on its next call.
  last_delta?: InvestigationDelta | null;
}

export interface InvestigationDelta {
  new_entity_ids: string[];
  new_relationship_ids: string[];
  enrichments: Array<{ entity_id: string; connector_id: string; status: string; new_object_ids: string[] }>;
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
  allowed_actions: InvestigationAutonomousAction[];
  enrichment_connector_ids: string[];
  approval_connector_ids: string[];
  auto_approve_low_risk: boolean;
  auto_approve_min_confidence: number;
  attribution_min_confidence: number;
  max_tool_calls: number;
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
  max_tool_calls: 40,
  max_enrichment_jobs: 20,
  max_minutes: 60,
  trigger_on_case_rfi_creation: false,
};

export const DEFAULT_POLICY_NAME = 'Default Case Autopilot policy';

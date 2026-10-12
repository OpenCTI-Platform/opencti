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

import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { createdAt, creators, refreshedAt, updatedAt } from '../../schema/attribute-definition';
import { objectMarking, objectOrganization } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_WORKSPACE } from '../workspace/workspace-types';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';
import {
  ENTITY_TYPE_INVESTIGATION_POLICY,
  ENTITY_TYPE_INVESTIGATION_RUN,
  INVESTIGATION_RUN_PHASES,
  INVESTIGATION_RUN_STATUSES,
  INVESTIGATION_RUN_TRIGGERS,
  type StixInvestigationRun,
  type StoreEntityInvestigationRun,
} from './investigationRun-types';
import { convertInvestigationRunToStix } from './investigationRun-converter';

// Ledger, matrix, timeline and the other run documents are stored as raw
// (non indexed) objects: they are bounded but free-form, and must never be
// mapped field by field nor hit the keyword length limit.
const rawList = (name: string, label: string) => ({
  name,
  label,
  type: 'object' as const,
  format: 'raw' as const,
  mandatoryType: 'internal' as const,
  editDefault: false,
  multiple: true,
  upsert: false,
  isFilterable: false,
});

const INVESTIGATION_RUN_DEFINITION: ModuleDefinition<StoreEntityInvestigationRun, StixInvestigationRun> = {
  type: {
    id: 'investigationRun',
    name: ENTITY_TYPE_INVESTIGATION_RUN,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INVESTIGATION_RUN]: () => uuidv4(),
    },
  },
  attributes: [
    createdAt,
    updatedAt,
    { ...refreshedAt, isFilterable: false },
    creators,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'subject_id', label: 'Investigated entity', type: 'string', format: 'id', entityTypes: [ABSTRACT_STIX_CORE_OBJECT], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'subject_type', label: 'Investigated entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'case_id', label: 'Case', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'case_ids', label: 'Case identifiers', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: true },
    { name: 'create_case', label: 'Create a case', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'context_ids', label: 'Context sent to the engine', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'workspace_id', label: 'Investigation graph', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_WORKSPACE], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'draft_id', label: 'Draft', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_DRAFT_WORKSPACE], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'policy_id', label: 'Policy', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_INVESTIGATION_POLICY], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'agent_slug', label: 'Agent', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pack_id', label: 'Investigation pack', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'xtm_investigation_id', label: 'Engine investigation', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'xtm_investigation_ids', label: 'Engine investigations', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'xtm_revision', label: 'Engine revision', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'xtm_status', label: 'Engine status', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'xtm_completed_at', label: 'Engine completion date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'continues_investigation_id', label: 'Continued investigation', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'budget_cancelled', label: 'Cancelled by the budget', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'run_trigger', label: 'Run trigger', type: 'string', format: 'enum', values: INVESTIGATION_RUN_TRIGGERS, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'run_status', label: 'Run status', type: 'string', format: 'enum', values: INVESTIGATION_RUN_STATUSES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'run_phase', label: 'Run phase', type: 'string', format: 'enum', values: INVESTIGATION_RUN_PHASES, mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'status_reason', label: 'Status reason', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'end_reason_code', label: 'End reason', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'started_at', label: 'Run start date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'completed_at', label: 'Run completion date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'active_ms', label: 'Active time', type: 'numeric', precision: 'long', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'running_since', label: 'Running since', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pending_work_ids', label: 'Pending works', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'wave_started_at', label: 'Validation start', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'validation_work_id', label: 'Draft validation work', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'engine_failures', label: 'Engine failures', type: 'numeric', precision: 'integer', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'step_failures', label: 'Interrupted steps', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'run_as_id', label: 'Run as', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'goal_plan', label: 'Goal plan', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    rawList('steps', 'Steps'),
    rawList('evidence', 'Evidence'),
    rawList('hypotheses', 'Hypotheses'),
    rawList('timeline', 'Timeline'),
    rawList('recommendations', 'Recommendations'),
    rawList('analyst_feedback', 'Analyst feedback'),
    rawList('approvals', 'Approvals'),
    rawList('enrichment_requests', 'Enrichment requests'),
    rawList('enrichment_waves', 'Enrichment waves'),
    rawList('report_sources', 'Report sources'),
    { name: 'budget', label: 'Budget', type: 'object', format: 'raw', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'outputs', label: 'Outputs', type: 'object', format: 'raw', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'summary', label: 'Summary', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'report', label: 'Report', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  // Markings and organizations of the investigated entity, its case and its
  // evidence are copied on the run, so the engine applies the same data
  // restrictions to the run (and to what the agent wrote about them).
  relationsRefs: [
    objectMarking,
    { ...objectOrganization, isFilterable: false },
  ],
  representative: (stix: StixInvestigationRun) => stix.name,
  converter_2_1: convertInvestigationRunToStix,
};

registerDefinition(INVESTIGATION_RUN_DEFINITION);

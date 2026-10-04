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
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { createdAt, creators, refreshedAt, updatedAt } from '../../schema/attribute-definition';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_INVESTIGATION_POLICY, INVESTIGATION_AUTONOMOUS_ACTIONS, type StixInvestigationPolicy, type StoreEntityInvestigationPolicy } from './investigationRun-types';
import { convertInvestigationPolicyToStix } from './investigationRun-converter';

const counter = (name: string, label: string) => ({
  name,
  label,
  type: 'numeric' as const,
  precision: 'integer' as const,
  mandatoryType: 'internal' as const,
  editDefault: false,
  multiple: false,
  upsert: false,
  isFilterable: false,
});

const INVESTIGATION_POLICY_DEFINITION: ModuleDefinition<StoreEntityInvestigationPolicy, StixInvestigationPolicy> = {
  type: {
    id: 'investigationPolicy',
    name: ENTITY_TYPE_INVESTIGATION_POLICY,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INVESTIGATION_POLICY]: () => uuidv4(),
    },
  },
  attributes: [
    createdAt,
    updatedAt,
    { ...refreshedAt, isFilterable: false },
    creators,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: true, multiple: false, upsert: false, isFilterable: false },
    { name: 'is_default', label: 'Default policy', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'agent_slug', label: 'Pinned agent', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pack_id', label: 'Investigation pack', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pack_options', label: 'Pack options', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'allowed_actions', label: 'Allowed autonomous actions', type: 'string', format: 'enum', values: INVESTIGATION_AUTONOMOUS_ACTIONS, mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'enrichment_connector_ids', label: 'Enrichment connectors allowed', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_CONNECTOR], mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'approval_connector_ids', label: 'Enrichment connectors requiring approval', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_CONNECTOR], mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'auto_approve_low_risk', label: 'Auto-approve low-risk drafts', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    counter('auto_approve_min_confidence', 'Auto-approval minimum confidence'),
    counter('attribution_min_confidence', 'Attribution minimum confidence'),
    counter('max_iterations', 'Maximum iterations'),
    counter('max_enrichment_jobs', 'Maximum enrichment jobs'),
    counter('max_minutes', 'Maximum duration in minutes'),
    { name: 'trigger_on_case_rfi_creation', label: 'Investigate new requests for information', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_event_id', label: 'Last stream event', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'run_as_id', label: 'Run as', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    counter('hypotheses_accepted', 'Accepted hypotheses'),
    counter('hypotheses_rejected', 'Rejected hypotheses'),
    counter('recommendations_accepted', 'Accepted recommendations'),
    counter('recommendations_rejected', 'Rejected recommendations'),
  ],
  relations: [],
  representative: (stix: StixInvestigationPolicy) => stix.name,
  converter_2_1: convertInvestigationPolicyToStix,
};

registerDefinition(INVESTIGATION_POLICY_DEFINITION);

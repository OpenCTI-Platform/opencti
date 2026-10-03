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

import type { InvestigationAutonomousAction } from './__generated__/InvestigationPoliciesAddMutation.graphql';

export const AUTONOMOUS_ACTIONS = ['enrichment', 'create_case', 'add_to_case', 'create_note', 'create_relationship'] as const;

export const AUTONOMOUS_ACTION_LABELS: Record<string, string> = {
  enrichment: 'Run enrichment connectors',
  create_case: 'Create a case',
  add_to_case: 'Add evidence to the case',
  create_note: 'Write the investigation summary note',
  create_relationship: 'Write the attribution relationship',
};

export interface Option {
  label: string;
  value: string;
}

export interface InvestigationPolicyFormValues {
  name: string;
  description: string;
  is_default: boolean;
  pack_id: string;
  agent_slug: string;
  allowed_actions: Option[];
  enrichment_connector_ids: Option[];
  approval_connector_ids: Option[];
  auto_approve_low_risk: boolean;
  auto_approve_min_confidence: number;
  attribution_min_confidence: number;
  max_tool_calls: number;
  max_enrichment_jobs: number;
  max_minutes: number;
  trigger_on_case_rfi_creation: boolean;
  run_as: Option | null;
}

/** A stored policy, as the settings page reads it. */
export interface InvestigationPolicyFormPolicy {
  readonly name: string;
  readonly description?: string | null;
  readonly is_default: boolean;
  readonly pack_id?: string | null;
  readonly agent_slug?: string | null;
  readonly allowed_actions: readonly string[];
  readonly enrichment_connector_ids: readonly string[];
  readonly approval_connector_ids: readonly string[];
  readonly auto_approve_low_risk: boolean;
  readonly auto_approve_min_confidence: number;
  readonly attribution_min_confidence: number;
  readonly max_tool_calls: number;
  readonly max_enrichment_jobs: number;
  readonly max_minutes: number;
  readonly trigger_on_case_rfi_creation: boolean;
  readonly runAs?: { readonly id: string; readonly name: string } | null;
}

// Same defaults as a policy created through the API.
export const NEW_POLICY: InvestigationPolicyFormPolicy = {
  name: '',
  description: '',
  is_default: false,
  pack_id: null,
  agent_slug: null,
  allowed_actions: [...AUTONOMOUS_ACTIONS],
  enrichment_connector_ids: [],
  approval_connector_ids: [],
  auto_approve_low_risk: false,
  auto_approve_min_confidence: 80,
  attribution_min_confidence: 55,
  max_tool_calls: 40,
  max_enrichment_jobs: 20,
  max_minutes: 60,
  trigger_on_case_rfi_creation: false,
  runAs: null,
};

export interface InvestigationPolicyInput {
  name: string;
  description: string | null;
  is_default: boolean;
  pack_id: string | null;
  agent_slug: string | null;
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
  run_as_id: string | null;
}

const toInteger = (value: unknown) => Number.parseInt(String(value), 10);
const orNull = (value: string | null | undefined) => (value && value.trim().length > 0 ? value.trim() : null);

export const toPolicyInput = (values: InvestigationPolicyFormValues): InvestigationPolicyInput => ({
  name: values.name.trim(),
  description: orNull(values.description),
  is_default: values.is_default,
  pack_id: orNull(values.pack_id),
  agent_slug: orNull(values.agent_slug),
  allowed_actions: values.allowed_actions.map((option) => option.value as InvestigationAutonomousAction),
  enrichment_connector_ids: values.enrichment_connector_ids.map((option) => option.value),
  approval_connector_ids: values.approval_connector_ids.map((option) => option.value),
  auto_approve_low_risk: values.auto_approve_low_risk,
  auto_approve_min_confidence: toInteger(values.auto_approve_min_confidence),
  attribution_min_confidence: toInteger(values.attribution_min_confidence),
  max_tool_calls: toInteger(values.max_tool_calls),
  max_enrichment_jobs: toInteger(values.max_enrichment_jobs),
  max_minutes: toInteger(values.max_minutes),
  trigger_on_case_rfi_creation: values.trigger_on_case_rfi_creation,
  run_as_id: values.run_as?.value ?? null,
});

const storedInput = (policy: InvestigationPolicyFormPolicy): InvestigationPolicyInput => ({
  name: policy.name,
  description: orNull(policy.description),
  is_default: policy.is_default,
  pack_id: orNull(policy.pack_id),
  agent_slug: orNull(policy.agent_slug),
  allowed_actions: policy.allowed_actions.map((action) => action as InvestigationAutonomousAction),
  enrichment_connector_ids: [...policy.enrichment_connector_ids],
  approval_connector_ids: [...policy.approval_connector_ids],
  auto_approve_low_risk: policy.auto_approve_low_risk,
  auto_approve_min_confidence: policy.auto_approve_min_confidence,
  attribution_min_confidence: policy.attribution_min_confidence,
  max_tool_calls: policy.max_tool_calls,
  max_enrichment_jobs: policy.max_enrichment_jobs,
  max_minutes: policy.max_minutes,
  trigger_on_case_rfi_creation: policy.trigger_on_case_rfi_creation,
  run_as_id: policy.runAs?.id ?? null,
});

const sameValue = (a: unknown, b: unknown) => {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && [...a].sort().join('\u0000') === [...b].sort().join('\u0000');
  }
  return a === b;
};

/** Only what changed, in the field patch shape: lists as lists, single values wrapped. */
export const toPolicyEditInputs = (policy: InvestigationPolicyFormPolicy, values: InvestigationPolicyFormValues) => {
  const before = storedInput(policy);
  const after = toPolicyInput(values);
  return (Object.keys(after) as (keyof InvestigationPolicyInput)[])
    .filter((key) => !sameValue(before[key], after[key]))
    .map((key) => {
      const value = after[key];
      return { key, value: Array.isArray(value) ? value : [value] };
    });
};

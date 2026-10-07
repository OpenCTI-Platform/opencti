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

import type { AuthContext, AuthUser } from '../../types/user';
import { type EditInput, FilterMode, type InvestigationPolicyAddInput, OrderingMode, type QueryInvestigationPoliciesArgs } from '../../generated/graphql';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { fullEntitiesList, internalLoadById, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { createEntity, patchAttribute } from '../../database/middleware';
import { deleteInternalObject, editInternalObject } from '../../domain/internalObject';
import { publishUserAction } from '../../listener/UserActionListener';
import { notify } from '../../database/redis';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';
import { elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { INVESTIGATION_MANAGER_USER } from '../../utils/access';
import { assertRunAsUserAllowed } from '../playbook/components/ai-agent-shared';
import { connectorsForEnrichment } from '../../database/repository';
import { addFilter } from '../../utils/filtering/filtering-utils';
import {
  ACTIVE_RUN_STATUSES,
  DEFAULT_POLICY_NAME,
  DEFAULT_POLICY_VALUES,
  ENTITY_TYPE_INVESTIGATION_POLICY,
  ENTITY_TYPE_INVESTIGATION_RUN,
  type BasicStoreEntityInvestigationPolicy,
  type InvestigationAcceptance,
  type StoreEntityInvestigationPolicy,
} from './investigationRun-types';

const DEFAULT_POLICY_LOCK = 'investigation_policy_default_lock';
const policyCountersLock = (policyId: string) => `investigation_policy_counters_${policyId}`;
const policyHookLock = (policyId: string) => `investigation_policy_hook_${policyId}`;
// Held by run creation and policy deletion: a policy is never deleted under a run being created.
export const policyUsageLockKey = (policyId: string) => `investigation_policy_usage_${policyId}`;

// Keys an administrator can edit; counters, stream position and default flag
// go through dedicated paths.
const EDITABLE_POLICY_KEYS = [
  'name',
  'description',
  'agent_slug',
  'pack_id',
  'allowed_actions',
  'enrichment_connector_ids',
  'approval_connector_ids',
  'auto_approve_low_risk',
  'auto_approve_min_confidence',
  'attribution_min_confidence',
  'max_iterations',
  'pack_options',
  'max_enrichment_jobs',
  'max_minutes',
  'trigger_on_case_rfi_creation',
  'run_as_id',
  'is_default',
];

const NUMERIC_BOUNDS: Record<string, [number, number]> = {
  auto_approve_min_confidence: [0, 100],
  attribution_min_confidence: [0, 100],
  max_iterations: [1, 50],
  max_enrichment_jobs: [0, 200],
  max_minutes: [1, 1440],
};

const assertNumericBounds = (key: string, value: unknown) => {
  const bounds = NUMERIC_BOUNDS[key];
  if (!bounds) return;
  const numeric = Number(value);
  if (!Number.isInteger(numeric) || numeric < bounds[0] || numeric > bounds[1]) {
    throw FunctionalError('Invalid investigation policy value', { key, min: bounds[0], max: bounds[1] });
  }
};

const MAX_PACK_OPTIONS = 20;
const MAX_PACK_OPTION_LENGTH = 100;

// The choices of a pack: option key -> chosen value, short strings only. The
// engine validates them against the pack; OpenCTI only bounds what it stores.
export const sanitizePackOptions = (value: unknown): Record<string, string> | null => {
  if (value === null || value === undefined || value === '') return null;
  const parsed = typeof value === 'string' ? (() => {
    try {
      return JSON.parse(value) as unknown;
    } catch {
      return null;
    }
  })() : value;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw FunctionalError('Pack options map an option to a value');
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length > MAX_PACK_OPTIONS) {
    throw FunctionalError('Too many pack options', { max: MAX_PACK_OPTIONS });
  }
  const options: Record<string, string> = {};
  entries.forEach(([key, optionValue]) => {
    if (typeof optionValue !== 'string' || key.length === 0 || key.length > MAX_PACK_OPTION_LENGTH || optionValue.length > MAX_PACK_OPTION_LENGTH) {
      throw FunctionalError('Invalid pack option', { key });
    }
    options[key] = optionValue;
  });
  return Object.keys(options).length > 0 ? options : null;
};

// Connectors referenced by a policy must be enrichment connectors.
const assertEnrichmentConnectors = async (context: AuthContext, user: AuthUser, connectorIds: string[]) => {
  if (connectorIds.length === 0) return;
  const enrichmentConnectors = await connectorsForEnrichment(context, user, null, false);
  const known = new Set(enrichmentConnectors.map((connector: { internal_id: string }) => connector.internal_id));
  const unknown = connectorIds.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    throw FunctionalError('Investigation policies only accept enrichment connectors', { connectorIds: unknown });
  }
};

// The enrichment connectors a policy can allow, for administrators who do not
// manage connectors themselves.
export const listInvestigationEnrichmentConnectors = async (context: AuthContext, user: AuthUser) => {
  await checkEnterpriseEdition(context);
  const connectors = await connectorsForEnrichment(context, user, null, false) as Array<{ internal_id: string; name: string; active?: boolean; connector_scope?: string[] }>;
  return connectors
    .map((connector) => ({ id: connector.internal_id, name: connector.name, active: connector.active === true, connector_scope: connector.connector_scope ?? [] }))
    .sort((a, b) => a.name.localeCompare(b.name));
};

export const findInvestigationPolicyById = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  return storeLoadById<BasicStoreEntityInvestigationPolicy>(context, user, id, ENTITY_TYPE_INVESTIGATION_POLICY);
};

export const findInvestigationPoliciesPaginated = async (context: AuthContext, user: AuthUser, args: QueryInvestigationPoliciesArgs) => {
  await checkEnterpriseEdition(context);
  return pageEntitiesConnection<BasicStoreEntityInvestigationPolicy>(context, user, [ENTITY_TYPE_INVESTIGATION_POLICY], {
    ...args,
    orderBy: args.orderBy ?? 'name',
    orderMode: args.orderMode ?? OrderingMode.Asc,
  });
};

export const loadInvestigationPolicy = (context: AuthContext, id: string) => {
  return internalLoadById<BasicStoreEntityInvestigationPolicy>(context, INVESTIGATION_MANAGER_USER, id, { type: ENTITY_TYPE_INVESTIGATION_POLICY });
};

const listDefaultPolicies = (context: AuthContext) => {
  return fullEntitiesList<BasicStoreEntityInvestigationPolicy>(context, INVESTIGATION_MANAGER_USER, [ENTITY_TYPE_INVESTIGATION_POLICY], {
    filters: { mode: FilterMode.And, filters: [{ key: ['is_default'], values: ['true'] }], filterGroups: [] },
  });
};

// Only one policy is the default: promoting one demotes the others.
const demoteOtherDefaults = async (context: AuthContext, keptId: string) => {
  const defaults = await listDefaultPolicies(context);
  await Promise.all(defaults
    .filter((policy) => policy.internal_id !== keptId)
    .map((policy) => patchAttribute(context, INVESTIGATION_MANAGER_USER, policy.internal_id, ENTITY_TYPE_INVESTIGATION_POLICY, { is_default: false })));
};

const buildPolicyInput = (input: Partial<InvestigationPolicyAddInput>) => ({
  name: input.name,
  description: input.description ?? null,
  is_default: input.is_default ?? false,
  agent_slug: input.agent_slug?.trim() || null,
  pack_id: input.pack_id?.trim() || null,
  pack_options: sanitizePackOptions(input.pack_options),
  allowed_actions: input.allowed_actions ?? DEFAULT_POLICY_VALUES.allowed_actions,
  enrichment_connector_ids: input.enrichment_connector_ids ?? DEFAULT_POLICY_VALUES.enrichment_connector_ids,
  approval_connector_ids: input.approval_connector_ids ?? DEFAULT_POLICY_VALUES.approval_connector_ids,
  auto_approve_low_risk: input.auto_approve_low_risk ?? DEFAULT_POLICY_VALUES.auto_approve_low_risk,
  auto_approve_min_confidence: input.auto_approve_min_confidence ?? DEFAULT_POLICY_VALUES.auto_approve_min_confidence,
  attribution_min_confidence: input.attribution_min_confidence ?? DEFAULT_POLICY_VALUES.attribution_min_confidence,
  max_iterations: input.max_iterations ?? DEFAULT_POLICY_VALUES.max_iterations,
  max_enrichment_jobs: input.max_enrichment_jobs ?? DEFAULT_POLICY_VALUES.max_enrichment_jobs,
  max_minutes: input.max_minutes ?? DEFAULT_POLICY_VALUES.max_minutes,
  trigger_on_case_rfi_creation: input.trigger_on_case_rfi_creation ?? DEFAULT_POLICY_VALUES.trigger_on_case_rfi_creation,
  // A new hook starts from now: requests for information created before are not investigated.
  last_event_id: `${Date.now()}-0`,
  run_as_id: input.run_as_id || null,
  hypotheses_accepted: 0,
  hypotheses_rejected: 0,
  recommendations_accepted: 0,
  recommendations_rejected: 0,
});

export const addInvestigationPolicy = async (context: AuthContext, user: AuthUser, input: InvestigationPolicyAddInput) => {
  await checkEnterpriseEdition(context);
  Object.keys(NUMERIC_BOUNDS).forEach((key) => {
    const value = (input as Record<string, unknown>)[key];
    if (value !== undefined && value !== null) assertNumericBounds(key, value);
  });
  // The hook and the playbook component run as this identity: same guardrail as the AI agent components.
  await assertRunAsUserAllowed(context, user, input.run_as_id ?? undefined);
  await assertEnrichmentConnectors(context, user, [...(input.enrichment_connector_ids ?? []), ...(input.approval_connector_ids ?? [])]);
  const lock = input.is_default ? await lockResources([DEFAULT_POLICY_LOCK]) : null;
  try {
    const created = await createEntity(context, user, buildPolicyInput(input), ENTITY_TYPE_INVESTIGATION_POLICY);
    if (input.is_default) {
      await demoteOtherDefaults(context, created.internal_id);
    }
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'create',
      event_access: 'administration',
      message: `creates investigation policy \`${created.name}\``,
      context_data: { id: created.internal_id, entity_type: ENTITY_TYPE_INVESTIGATION_POLICY, input },
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_POLICY].ADDED_TOPIC, created, user);
  } finally {
    if (lock) await lock.unlock();
  }
};

export const editInvestigationPolicy = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  await checkEnterpriseEdition(context);
  const forbidden = input.filter(({ key }) => !EDITABLE_POLICY_KEYS.includes(key));
  if (forbidden.length > 0) {
    throw FunctionalError('Invalid or forbidden investigation policy key', { keys: forbidden.map(({ key }) => key) });
  }
  input.forEach(({ key, value }) => assertNumericBounds(key, value?.[0]));
  const runAsInput = input.find(({ key }) => key === 'run_as_id');
  if (runAsInput) {
    await assertRunAsUserAllowed(context, user, (runAsInput.value?.[0] as string | undefined) ?? undefined);
  }
  const connectorInputs = input.filter(({ key }) => key === 'enrichment_connector_ids' || key === 'approval_connector_ids');
  await assertEnrichmentConnectors(context, user, connectorInputs.flatMap(({ value }) => (value ?? []) as string[]));
  const defaultInput = input.find(({ key }) => key === 'is_default');
  const becomesDefault = defaultInput && String(defaultInput.value?.[0]) === 'true';
  if (defaultInput && !becomesDefault) {
    const current = await loadInvestigationPolicy(context, id);
    if (current?.is_default) {
      throw FunctionalError('Promote another policy to default instead of removing the default flag', { id });
    }
  }
  const finalInput = input.map((entry) => (entry.key === 'pack_options' ? { ...entry, value: [sanitizePackOptions(entry.value?.[0])] } : entry));
  const hookInput = input.find(({ key }) => key === 'trigger_on_case_rfi_creation');
  const enablesHook = hookInput && String(hookInput.value?.[0]) === 'true';
  // The hook cursor and the default flag are changed under their locks, the
  // cursor with the manager that advances it.
  const lockKeys = [...(becomesDefault ? [DEFAULT_POLICY_LOCK] : []), ...(enablesHook ? [policyHookLock(id)] : [])];
  const lock = lockKeys.length > 0 ? await lockResources(lockKeys) : null;
  try {
    if (enablesHook && !(await loadInvestigationPolicy(context, id))?.trigger_on_case_rfi_creation) {
      // Turning the hook on starts from now, never replays the past; a hook already on keeps its cursor.
      finalInput.push({ key: 'last_event_id', value: [`${Date.now()}-0`] });
    }
    const element = await editInternalObject<StoreEntityInvestigationPolicy>(context, user, id, ENTITY_TYPE_INVESTIGATION_POLICY, finalInput);
    if (becomesDefault) {
      await demoteOtherDefaults(context, id);
    }
    return notify(BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_POLICY].EDIT_TOPIC, element, user);
  } finally {
    if (lock) await lock.unlock();
  }
};

// Every run counts, including the ones the caller cannot read.
const countActiveRunsForPolicy = (context: AuthContext, policyId: string): Promise<number> => {
  return elCount(context, INVESTIGATION_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_INVESTIGATION_RUN],
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['policy_id'], values: [policyId] }, { key: ['run_status'], values: ACTIVE_RUN_STATUSES }],
      filterGroups: [],
    },
  });
};

export const deleteInvestigationPolicy = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkEnterpriseEdition(context);
  const policy = await loadInvestigationPolicy(context, id);
  if (!policy) {
    throw FunctionalError('Investigation policy not found', { id });
  }
  if (policy.is_default) {
    throw FunctionalError('The default investigation policy cannot be deleted', { id });
  }
  // The default lock too: a concurrent promotion cannot make it the default between the check and the deletion.
  const lock = await lockResources([DEFAULT_POLICY_LOCK, policyUsageLockKey(policy.internal_id)]);
  try {
    const current = await loadInvestigationPolicy(context, id);
    if (!current) {
      throw FunctionalError('Investigation policy not found', { id });
    }
    if (current.is_default) {
      throw FunctionalError('The default investigation policy cannot be deleted', { id });
    }
    // Runs read their policy on every step: it stays until they end.
    const activeRuns = await countActiveRunsForPolicy(context, policy.internal_id);
    if (activeRuns > 0) {
      throw FunctionalError('The investigation policy is used by investigations in progress', { id, activeRuns });
    }
    await deleteInternalObject(context, user, id, ENTITY_TYPE_INVESTIGATION_POLICY);
  } finally {
    await lock.unlock();
  }
  await notify(BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_POLICY].DELETE_TOPIC, policy, user);
  return id;
};

/**
 * The default policy, created on first use (and by the platform
 * initialization and migration) so a run always has budgets and gates.
 */
export const getDefaultInvestigationPolicy = async (context: AuthContext): Promise<BasicStoreEntityInvestigationPolicy> => {
  const existing = await listDefaultPolicies(context);
  if (existing.length > 0) {
    return existing[0];
  }
  const lock = await lockResources([DEFAULT_POLICY_LOCK]);
  try {
    const raced = await listDefaultPolicies(context);
    if (raced.length > 0) {
      return raced[0];
    }
    const created = await createEntity(
      context,
      INVESTIGATION_MANAGER_USER,
      buildPolicyInput({
        name: DEFAULT_POLICY_NAME,
        description: 'Applied to every Case Autopilot run that does not select another policy.',
        is_default: true,
      }),
      ENTITY_TYPE_INVESTIGATION_POLICY,
    );
    logApp.info('[CASE AUTOPILOT] Default investigation policy created', { id: created.internal_id });
    return created;
  } finally {
    await lock.unlock();
  }
};

export const listCaseRfiTriggerPolicies = (context: AuthContext) => {
  return fullEntitiesList<BasicStoreEntityInvestigationPolicy>(context, INVESTIGATION_MANAGER_USER, [ENTITY_TYPE_INVESTIGATION_POLICY], {
    filters: { mode: FilterMode.And, filters: [{ key: ['trigger_on_case_rfi_creation'], values: ['true'] }], filterGroups: [] },
  });
};

/**
 * Move the request for information hook cursor from `fromEventId` to
 * `lastEventId`, only if the hook is still on and nobody moved the cursor
 * meanwhile (an analyst re-enabling the hook restarts it from that moment).
 */
export const updateInvestigationPolicyStreamPosition = async (context: AuthContext, id: string, fromEventId: string, lastEventId: string) => {
  const lock = await lockResources([policyHookLock(id)]);
  try {
    const policy = await loadInvestigationPolicy(context, id);
    if (!policy?.trigger_on_case_rfi_creation || (policy.last_event_id && policy.last_event_id !== fromEventId)) {
      return false;
    }
    await patchAttribute(context, INVESTIGATION_MANAGER_USER, id, ENTITY_TYPE_INVESTIGATION_POLICY, { last_event_id: lastEventId });
    return true;
  } finally {
    await lock.unlock();
  }
};

// Apply an acceptance delta atomically, the counters back the acceptance rate of the policy.
export const applyInvestigationPolicyAcceptanceDelta = async (context: AuthContext, id: string, delta: InvestigationAcceptance) => {
  const keys = Object.keys(delta) as Array<keyof InvestigationAcceptance>;
  if (keys.every((key) => delta[key] === 0)) return;
  const lock = await lockResources([policyCountersLock(id)]);
  try {
    const policy = await loadInvestigationPolicy(context, id);
    if (!policy) return;
    const patch: Record<string, number> = {};
    keys.forEach((key) => {
      patch[key] = Math.max(0, (policy[key] ?? 0) + delta[key]);
    });
    const { element } = await patchAttribute(context, INVESTIGATION_MANAGER_USER, id, ENTITY_TYPE_INVESTIGATION_POLICY, patch);
    await notify(BUS_TOPICS[ENTITY_TYPE_INVESTIGATION_POLICY].EDIT_TOPIC, element, INVESTIGATION_MANAGER_USER);
  } finally {
    await lock.unlock();
  }
};

export const countInvestigationRunsForPolicy = (context: AuthContext, user: AuthUser, policyId: string) => {
  return elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_INVESTIGATION_RUN],
    filters: addFilter(undefined, 'policy_id', [policyId]),
  });
};

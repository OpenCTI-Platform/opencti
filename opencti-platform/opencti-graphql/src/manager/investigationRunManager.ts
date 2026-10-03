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

// Case Autopilot manager: advances every active investigation run by one
// phase per tick (state machine in modules/investigationRun) and starts runs
// on new requests for information for the policies that ask for it.

import { Promise as BluePromise } from 'bluebird';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { EVENT_TYPE_CREATE } from '../database/utils';
import { fetchStreamEventsRangeFromEventId } from '../database/stream/stream-handler';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import { InvestigationRunTrigger } from '../generated/graphql';
import { resolveUserByIdFromCache } from '../modules/user/user-domain';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { INVESTIGATION_MANAGER_CONTEXT, listInvestigationRunsToProcess, processInvestigationRun } from '../modules/investigationRun/investigationRun-executor';
import { addInvestigationRun } from '../modules/investigationRun/investigationRun-domain';
import { listCaseRfiTriggerPolicies, updateInvestigationPolicyStreamPosition } from '../modules/investigationRun/investigationPolicy-domain';
import type { BasicStoreEntityInvestigationPolicy } from '../modules/investigationRun/investigationRun-types';

const INVESTIGATION_RUN_MANAGER_ID = 'INVESTIGATION_RUN_MANAGER';
const INVESTIGATION_RUN_MANAGER_LABEL = 'Case Autopilot manager';
const INVESTIGATION_RUN_MANAGER_ENABLED = booleanConf('investigation_run_manager:enabled', true);
const INVESTIGATION_RUN_MANAGER_LOCK_KEY = conf.get('investigation_run_manager:lock_key') || 'investigation_run_manager_lock';
const INVESTIGATION_RUN_MANAGER_INTERVAL = conf.get('investigation_run_manager:interval') ?? 10000;
const INVESTIGATION_RUN_MANAGER_MAX_CONCURRENCY = conf.get('investigation_run_manager:max_concurrency') ?? 3;
const INVESTIGATION_RUN_MANAGER_MAX_RUNS_PER_TICK = conf.get('investigation_run_manager:max_runs_per_tick') ?? 50;
const INVESTIGATION_RUN_MANAGER_STREAM_BATCH_SIZE = conf.get('investigation_run_manager:stream_batch_size') ?? 2000;

// The hook runs as the policy identity, like the AI agent playbook components
// default to the seeded platform admin when none is configured. A configured
// identity that no longer exists never falls back to the administrator.
export const resolveHookUser = async (context: AuthContext, policy: BasicStoreEntityInvestigationPolicy) => {
  if (policy.run_as_id) {
    return resolveUserByIdFromCache(context, policy.run_as_id);
  }
  return resolveUserByIdFromCache(context, OPENCTI_ADMIN_UUID);
};

const caseRfiCreationHandler = (context: AuthContext, policy: BasicStoreEntityInvestigationPolicy) => {
  return async (streamEvents: Array<SseEvent<DataEvent>>) => {
    const created = streamEvents
      .map((event) => event.data)
      .filter((event) => event.type === EVENT_TYPE_CREATE && event.data?.extensions?.[STIX_EXT_OCTI]?.type === ENTITY_TYPE_CONTAINER_CASE_RFI);
    if (created.length === 0) return;
    const runUser = await resolveHookUser(context, policy);
    if (!runUser) {
      logApp.warn('[CASE AUTOPILOT] No identity to investigate new requests for information', { policyId: policy.internal_id });
      return;
    }
    for (let index = 0; index < created.length; index += 1) {
      const rfiId = created[index].data.extensions[STIX_EXT_OCTI].id;
      try {
        await addInvestigationRun(context, runUser, rfiId, policy.internal_id, { trigger: InvestigationRunTrigger.CaseRfiCreation, runAsUserId: runUser.id });
      } catch (error) {
        logApp.warn('[CASE AUTOPILOT] Investigation of a new request for information not started', { rfiId, policyId: policy.internal_id, cause: error });
      }
    }
  };
};

const processCaseRfiHooks = async (context: AuthContext) => {
  const policies = await listCaseRfiTriggerPolicies(context);
  for (let index = 0; index < policies.length; index += 1) {
    const policy = policies[index];
    const startEventId = policy.last_event_id || `${Date.now()}-0`;
    const { lastEventId } = await fetchStreamEventsRangeFromEventId(
      startEventId,
      caseRfiCreationHandler(context, policy),
      { streamBatchSize: INVESTIGATION_RUN_MANAGER_STREAM_BATCH_SIZE },
    );
    if (lastEventId && lastEventId !== policy.last_event_id) {
      await updateInvestigationPolicyStreamPosition(context, policy.internal_id, lastEventId);
    }
  }
};

export const investigationRunManagerHandler = async () => {
  const context = executionContext(INVESTIGATION_MANAGER_CONTEXT);
  try {
    await processCaseRfiHooks(context);
  } catch (error) {
    logApp.error('[CASE AUTOPILOT] Request for information hook error', { cause: error });
  }
  const runs = await listInvestigationRunsToProcess(context, INVESTIGATION_RUN_MANAGER_MAX_RUNS_PER_TICK);
  await BluePromise.map(runs, (run) => processInvestigationRun(context, run.internal_id), { concurrency: INVESTIGATION_RUN_MANAGER_MAX_CONCURRENCY });
};

const INVESTIGATION_RUN_MANAGER_DEFINITION: ManagerDefinition = {
  id: INVESTIGATION_RUN_MANAGER_ID,
  label: INVESTIGATION_RUN_MANAGER_LABEL,
  executionContext: INVESTIGATION_MANAGER_CONTEXT,
  enterpriseEditionOnly: true,
  cronSchedulerHandler: {
    handler: investigationRunManagerHandler,
    interval: INVESTIGATION_RUN_MANAGER_INTERVAL,
    lockKey: INVESTIGATION_RUN_MANAGER_LOCK_KEY,
  },
  enabledByConfig: INVESTIGATION_RUN_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(INVESTIGATION_RUN_MANAGER_DEFINITION);

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
import { ALREADY_DELETED_ERROR, FORBIDDEN_ACCESS, FUNCTIONAL_ERROR, MISSING_REF_ERROR, VALIDATION_ERROR } from '../config/errors';
import { executionContext } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { EVENT_TYPE_CREATE } from '../database/utils';
import { fetchStreamEventsRangeFromEventId } from '../database/stream/stream-handler';
import { OPENCTI_ADMIN_UUID } from '../schema/general';
import { InvestigationRunTrigger } from '../generated/graphql';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import {
  INVESTIGATION_MANAGER_CONTEXT,
  listAwaitingInvestigationRunsToRevalidate,
  listInvestigationRunsToProcess,
  processInvestigationRun,
  revalidateAwaitingInvestigationRun,
} from '../modules/investigationRun/investigationRun-executor';
import { addInvestigationRun, investigationIdentityContext, resolveRunIdentity } from '../modules/investigationRun/investigationRun-domain';
import { listCaseRfiTriggerPolicies, updateInvestigationPolicyStreamPosition } from '../modules/investigationRun/investigationPolicy-domain';
import type { BasicStoreEntityInvestigationPolicy } from '../modules/investigationRun/investigationRun-types';

const INVESTIGATION_RUN_MANAGER_ID = 'INVESTIGATION_RUN_MANAGER';
const INVESTIGATION_RUN_MANAGER_LABEL = 'Case Autopilot manager';
const INVESTIGATION_RUN_MANAGER_ENABLED = booleanConf('investigation_run_manager:enabled', true);
const INVESTIGATION_RUN_MANAGER_LOCK_KEY = conf.get('investigation_run_manager:lock_key') || 'investigation_run_manager_lock';
const INVESTIGATION_RUN_MANAGER_INTERVAL = conf.get('investigation_run_manager:interval') ?? 10000;
const INVESTIGATION_RUN_MANAGER_MAX_CONCURRENCY = conf.get('investigation_run_manager:max_concurrency') ?? 3;
const INVESTIGATION_RUN_MANAGER_MAX_RUNS_PER_TICK = conf.get('investigation_run_manager:max_runs_per_tick') ?? 50;
const INVESTIGATION_RUN_MANAGER_MAX_AWAITING_RUNS_PER_TICK = conf.get('investigation_run_manager:max_awaiting_runs_per_tick') ?? 10;
const INVESTIGATION_RUN_MANAGER_STREAM_BATCH_SIZE = conf.get('investigation_run_manager:stream_batch_size') ?? 2000;

// The hook runs as the policy identity, like the AI agent playbook components
// default to the seeded platform admin when none is configured. A configured
// identity that no longer exists or can no longer use the platform never falls
// back to the administrator.
export const resolveHookUser = async (context: AuthContext, policy: BasicStoreEntityInvestigationPolicy) => {
  if (policy.run_as_id) {
    return resolveRunIdentity(context, policy.run_as_id);
  }
  return resolveRunIdentity(context, OPENCTI_ADMIN_UUID);
};

// A refusal (the request is gone, not investigable, not visible to the
// identity) never succeeds on a retry; any other failure (database, lock
// timeout, unknown) is retried.
const HOOK_REFUSAL_CODES = [FUNCTIONAL_ERROR, FORBIDDEN_ACCESS, MISSING_REF_ERROR, ALREADY_DELETED_ERROR, VALIDATION_ERROR];
export const isRetryableHookError = (error: unknown) => {
  const code = (error as { extensions?: { code?: string } })?.extensions?.code;
  return !code || !HOOK_REFUSAL_CODES.includes(code);
};

export interface CaseRfiHookProgress {
  // Last stream event fully handled, where the next tick resumes after a retryable failure.
  handledEventId: string | null;
  retry: boolean;
}

export const caseRfiCreationHandler = (context: AuthContext, policy: BasicStoreEntityInvestigationPolicy, progress: CaseRfiHookProgress) => {
  return async (streamEvents: Array<SseEvent<DataEvent>>) => {
    const isRfiCreation = ({ data: event }: SseEvent<DataEvent>) => event.type === EVENT_TYPE_CREATE
      && event.data?.extensions?.[STIX_EXT_OCTI]?.type === ENTITY_TYPE_CONTAINER_CASE_RFI;
    const hasRfiCreation = streamEvents.some(isRfiCreation);
    const runUser = hasRfiCreation ? await resolveHookUser(context, policy) : null;
    const runContext = runUser ? await investigationIdentityContext(INVESTIGATION_MANAGER_CONTEXT, runUser) : null;
    for (let index = 0; index < streamEvents.length && !progress.retry; index += 1) {
      const streamEvent = streamEvents[index];
      if (isRfiCreation(streamEvent) && !runUser) {
        // Retried once the identity of the policy resolves again: the cursor stays before this request.
        logApp.warn('[CASE AUTOPILOT] No identity to investigate new requests for information, retried on the next run', { policyId: policy.internal_id });
        progress.retry = true;
        return;
      }
      if (runUser && runContext && isRfiCreation(streamEvent)) {
        const rfiId = streamEvent.data.data.extensions[STIX_EXT_OCTI].id;
        try {
          // Launched as the policy identity: the request is read with its platform organization membership.
          await addInvestigationRun(runContext, runUser, rfiId, policy.internal_id, { trigger: InvestigationRunTrigger.CaseRfiCreation, runAsUserId: runUser.id });
        } catch (error) {
          if (isRetryableHookError(error)) {
            logApp.warn('[CASE AUTOPILOT] Investigation of a new request for information delayed, retried on the next run', { rfiId, policyId: policy.internal_id, cause: error });
            progress.retry = true;
            return;
          }
          logApp.warn('[CASE AUTOPILOT] Investigation of a new request for information not started', { rfiId, policyId: policy.internal_id, cause: error });
        }
      }
      progress.handledEventId = streamEvent.id;
    }
  };
};

// Where the hook of a policy reads from: its stored position, else now. The
// progress starts there, so a failure on the very first event keeps that position.
export const startCaseRfiHook = (policy: Pick<BasicStoreEntityInvestigationPolicy, 'last_event_id'>, now = Date.now()) => {
  const startEventId = policy.last_event_id || `${now}-0`;
  const progress: CaseRfiHookProgress = { handledEventId: startEventId, retry: false };
  return { startEventId, progress };
};

// After a retryable failure the cursor stops on the last handled event, never past the failed one.
export const nextCaseRfiHookPosition = (progress: CaseRfiHookProgress, lastEventId: string | null | undefined) => {
  return (progress.retry ? progress.handledEventId : lastEventId) ?? null;
};

const processCaseRfiHooks = async (context: AuthContext) => {
  const policies = await listCaseRfiTriggerPolicies(context);
  for (let index = 0; index < policies.length; index += 1) {
    const policy = policies[index];
    const { startEventId, progress } = startCaseRfiHook(policy);
    const { lastEventId } = await fetchStreamEventsRangeFromEventId(
      startEventId,
      caseRfiCreationHandler(context, policy, progress),
      { streamBatchSize: INVESTIGATION_RUN_MANAGER_STREAM_BATCH_SIZE },
    );
    const position = nextCaseRfiHookPosition(progress, lastEventId);
    if (position && position !== policy.last_event_id) {
      await updateInvestigationPolicyStreamPosition(context, policy.internal_id, policy.last_event_id ?? '', position);
    }
  }
};

export const investigationRunManagerHandler = async () => {
  const context = executionContext(INVESTIGATION_MANAGER_CONTEXT);
  try {
    await processCaseRfiHooks(context);
  } catch (error) {
    // A policy cursor moves only after its events were handled: the next tick retries from it.
    logApp.warn('[CASE AUTOPILOT] Request for information hook delayed, retried at the next tick', { cause: error });
  }
  const runs = await listInvestigationRunsToProcess(context, INVESTIGATION_RUN_MANAGER_MAX_RUNS_PER_TICK);
  await BluePromise.map(runs, (run) => processInvestigationRun(context, run.internal_id), { concurrency: INVESTIGATION_RUN_MANAGER_MAX_CONCURRENCY });
  const awaiting = await listAwaitingInvestigationRunsToRevalidate(context, INVESTIGATION_RUN_MANAGER_MAX_AWAITING_RUNS_PER_TICK);
  await BluePromise.map(awaiting, (run) => revalidateAwaitingInvestigationRun(context, run.internal_id), { concurrency: INVESTIGATION_RUN_MANAGER_MAX_CONCURRENCY });
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

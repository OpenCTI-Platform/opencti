import type { AuthContext } from '../../types/user';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import { logApp } from '../../config/conf';
import { stixLoadByIds } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { AUTOMATION_MANAGER_USER, HUNT_MANAGER_USER } from '../../utils/access';
import { resolveUserByIdFromCache } from '../user/user-domain';
import { listHuntConnectors } from './hunt-dispatch';
import { isTerminalHuntRunFailure } from './hunt-logic';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_RUN_STATUS_COMPLETED,
  HUNT_RUN_TERMINAL_STATUSES,
  type HuntPlaybookContext,
  HUNT_VERDICT_PENDING,
} from './huntRun/huntRun-types';

export const PLAYBOOK_HUNT_COMPONENT_ID = 'PLAYBOOK_HUNT_COMPONENT';
// Objects produced by the runs and appended to the playbook bundle when the step resumes
export const HUNT_PLAYBOOK_MAX_RESULTS = 500;
// The continuation keeps the bundle of the step: oversized bundles are resumed immediately instead of waiting
export const HUNT_PLAYBOOK_MAX_CONTEXT_LENGTH = 5 * 1024 * 1024;

export interface PlaybookHuntRunsScope {
  executionId: string;
  // Entity the execution processes: one step runs concurrently for several entities, each waits on its own runs only
  instanceId: string | null | undefined;
  stepId?: string | null;
}

/**
 * Runs started for one entity by one hunt step of one playbook execution (retries included). Without a step id, every
 * hunt run of the execution for this entity is returned (a result filter placed after other steps).
 */
export const findPlaybookHuntRuns = async (context: AuthContext, scope: PlaybookHuntRunsScope) => {
  const filters: { key: string[]; values: string[]; operator?: FilterOperator }[] = [
    { key: ['playbook_execution_id'], values: [scope.executionId] },
    scope.instanceId
      ? { key: ['playbook_instance_id'], values: [scope.instanceId] }
      : { key: ['playbook_instance_id'], values: [], operator: FilterOperator.Nil },
  ];
  if (scope.stepId) {
    filters.push({ key: ['playbook_step_id'], values: [scope.stepId] });
  }
  return fullEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
    noFiltersChecking: true,
  });
};

// A group of runs is settled when every run is terminated and no automatic retry is still planned
export const isHuntRunGroupSettled = (runs: Pick<BasicStoreEntityHuntRun, 'hunt_run_status' | 'next_retry_at'>[]) => {
  return runs.every((run) => HUNT_RUN_TERMINAL_STATUSES.includes(run.hunt_run_status) && !run.next_retry_at);
};

export interface HuntPlaybookOutcome {
  runs_count: number;
  completed_count: number;
  hits_total: number;
  verdicts: string[];
  proposed_verdicts: string[];
  incident_ids: string[];
}

// A retry is the next attempt of the same hunt, step, connector and window: anything else is a distinct run
const huntRunRetryChainKey = (run: BasicStoreEntityHuntRun) => {
  const windowStart = run.time_window_start ? new Date(run.time_window_start).toISOString() : '';
  return [run.hunt_id, run.playbook_step_id ?? '', run.connector_id ?? '', windowStart].join(':');
};

/**
 * Outcome of the hunt runs of a playbook execution. A retried run only counts through its last attempt: superseded
 * failed attempts are ignored when a later attempt exists in the same retry chain.
 */
export const computeHuntPlaybookOutcome = (runs: BasicStoreEntityHuntRun[]): HuntPlaybookOutcome => {
  const latest = new Map<string, BasicStoreEntityHuntRun>();
  runs.forEach((run) => {
    const key = huntRunRetryChainKey(run);
    const current = latest.get(key);
    if (!current || (run.attempt ?? 1) > (current.attempt ?? 1)) {
      latest.set(key, run);
    }
  });
  const effective = Array.from(latest.values());
  // A run that failed for good has no verdict to match: its pending verdict never waits for a review
  const judged = effective.filter((run) => !isTerminalHuntRunFailure(run));
  return {
    runs_count: effective.length,
    completed_count: effective.filter((run) => run.hunt_run_status === HUNT_RUN_STATUS_COMPLETED).length,
    hits_total: effective.reduce((sum, run) => sum + (run.hits_count ?? 0), 0),
    verdicts: Array.from(new Set(judged.map((run) => run.verdict))),
    proposed_verdicts: Array.from(new Set(judged
      .map((run) => (run.verdict === HUNT_VERDICT_PENDING && run.verdict_proposal ? run.verdict_proposal : run.verdict)))),
    incident_ids: Array.from(new Set(effective.map((run) => run.incident_id).filter((id): id is string => !!id))),
  };
};

/**
 * Continues a playbook execution waiting on a hunt step (PLAYBOOK_HUNT_COMPONENT): the step executor runs with the
 * bundle of the step, completed with the knowledge produced by the runs when configured.
 */
/**
 * Objects recorded by the runs, loaded with the identity of the hunt connector of each run. The playbook processes
 * them with the automation identity: an object the connector cannot read itself is never added to the bundle.
 */
export const loadHuntRunResultsForPlaybook = async (context: AuthContext, runs: BasicStoreEntityHuntRun[], knownIds: Set<string>) => {
  const connectorUsers = new Map((await listHuntConnectors(context, false)).map((connector) => [connector.internal_id, connector.connector_user_id]));
  const idsByUser = new Map<string, string[]>();
  const taken = new Set<string>(knownIds);
  let count = 0;
  runs.forEach((run) => {
    const userId = run.connector_id ? connectorUsers.get(run.connector_id) : undefined;
    if (!userId) {
      if ((run.result_ids ?? []).length > 0) {
        logApp.warn('[OPENCTI-MODULE] Hunt run results skipped, the hunt connector of the run has no user', { runId: run.internal_id, connectorId: run.connector_id });
      }
      return;
    }
    const userIds = idsByUser.get(userId) ?? [];
    (run.result_ids ?? []).forEach((id) => {
      if (count < HUNT_PLAYBOOK_MAX_RESULTS && !taken.has(id)) {
        taken.add(id);
        count += 1;
        userIds.push(id);
      }
    });
    if (userIds.length > 0) {
      idsByUser.set(userId, userIds);
    }
  });
  const results: StixObject[] = [];
  const groups = Array.from(idsByUser.entries());
  for (let index = 0; index < groups.length; index += 1) {
    const [userId, ids] = groups[index];
    const connectorUser = await resolveUserByIdFromCache(context, userId);
    if (connectorUser) {
      const loaded = await stixLoadByIds(context, connectorUser, ids) as StixObject[];
      results.push(...loaded.filter((result) => !!result));
    } else {
      logApp.warn('[OPENCTI-MODULE] Hunt run results skipped, the user of the hunt connector cannot be found', { userId });
    }
  }
  return results;
};

export const resumeHuntPlaybookStep = async (context: AuthContext, playbookContext: HuntPlaybookContext, runs: BasicStoreEntityHuntRun[]) => {
  const bundle = JSON.parse(playbookContext.bundle) as StixBundle;
  if (playbookContext.include_results) {
    const knownIds = new Set<string>(bundle.objects.map((object) => object.id));
    bundle.objects.push(...await loadHuntRunResultsForPlaybook(context, runs, knownIds));
  }
  // Imported lazily: the playbook manager loads the playbook components, this module included
  const { playbookStepExecution } = await import('../../manager/playbookManager/playbookManager');
  const resumed = await playbookStepExecution(context, AUTOMATION_MANAGER_USER, {
    playbook_id: playbookContext.playbook_id,
    step_id: playbookContext.step_id,
    previous_step_id: playbookContext.previous_step_id,
    execution_id: playbookContext.execution_id,
    event_id: playbookContext.event_id,
    data_instance_id: playbookContext.data_instance_id,
    execution_start: playbookContext.execution_start,
    previous_bundle: playbookContext.previous_bundle,
    bundle: JSON.stringify(bundle),
  });
  if (!resumed) {
    logApp.warn('[OPENCTI-MODULE] Hunt playbook step cannot be resumed, the playbook or its step does not exist anymore', {
      playbookId: playbookContext.playbook_id,
      stepId: playbookContext.step_id,
    });
  }
  return resumed;
};

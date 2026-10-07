import type { AuthContext } from '../../types/user';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { ExecutionEnvelop } from '../../types/playbookExecution';
import { logApp } from '../../config/conf';
import { stixLoadByIds } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { redisPlaybookUpdate } from '../../database/redis';
import { FilterMode, FilterOperator, type MutationPlaybookStepExecutionArgs } from '../../generated/graphql';
import { AUTOMATION_MANAGER_USER, HUNT_MANAGER_USER } from '../../utils/access';
import { now } from '../../utils/format';
import { resolveUserByIdFromCache } from '../user/user-domain';
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
// The continuation keeps the bundles of the step: a step whose context would be oversized is resumed immediately instead of waiting
export const HUNT_PLAYBOOK_MAX_CONTEXT_LENGTH = 5 * 1024 * 1024;

/** Whether the continuation of a step can wait on its leader run: its whole context as stored, both bundles included. */
export const isStorableHuntPlaybookContext = (playbookContext: HuntPlaybookContext) => {
  return JSON.stringify(playbookContext).length <= HUNT_PLAYBOOK_MAX_CONTEXT_LENGTH;
};

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
 * Objects recorded by the runs, loaded with the identity the hunt connector of each run ran as when the run was
 * dispatched, the only one that reports the run. The playbook processes them with the automation identity: an object
 * the connector cannot read itself is never added to the bundle, even once the connector is registered again as
 * another user. The cap and the deduplication apply to the objects loaded, so an id an identity cannot read (deleted,
 * or out of its reach) takes no place and never keeps another identity that reads it from adding it. Known ids are
 * internal ids (as the runs record them) or STIX ids (as the bundle holds them).
 */
export const loadHuntRunResultsForPlaybook = async (context: AuthContext, runs: BasicStoreEntityHuntRun[], knownIds: Set<string>) => {
  const idsByUser = new Map<string, string[]>();
  runs.forEach((run) => {
    const resultIds = run.result_ids ?? [];
    const userId = run.connector_user_id;
    if (!userId) {
      if (resultIds.length > 0) {
        logApp.warn('[OPENCTI-MODULE] Hunt run results skipped, the run has no hunt connector user', { runId: run.internal_id, connectorId: run.connector_id });
      }
      return;
    }
    if (resultIds.length > 0) {
      idsByUser.set(userId, [...(idsByUser.get(userId) ?? []), ...resultIds]);
    }
  });
  const taken = new Set<string>(knownIds);
  const results: StixObject[] = [];
  const groups = Array.from(idsByUser.entries());
  for (let index = 0; index < groups.length && results.length < HUNT_PLAYBOOK_MAX_RESULTS; index += 1) {
    const [userId, ids] = groups[index];
    const connectorUser = await resolveUserByIdFromCache(context, userId);
    if (connectorUser) {
      const pending = Array.from(new Set(ids)).filter((id) => !taken.has(id));
      for (let start = 0; start < pending.length && results.length < HUNT_PLAYBOOK_MAX_RESULTS; start += HUNT_PLAYBOOK_MAX_RESULTS) {
        const loaded = await stixLoadByIds(context, connectorUser, pending.slice(start, start + HUNT_PLAYBOOK_MAX_RESULTS)) as StixObject[];
        loaded.filter((result) => !!result).forEach((result) => {
          const internalId = result.extensions?.[STIX_EXT_OCTI]?.id;
          if (results.length < HUNT_PLAYBOOK_MAX_RESULTS && !taken.has(result.id) && !(internalId && taken.has(internalId))) {
            taken.add(result.id);
            if (internalId) {
              taken.add(internalId);
            }
            results.push(result);
          }
        });
      }
    } else {
      logApp.warn('[OPENCTI-MODULE] Hunt run results skipped, the user of the hunt connector cannot be found', { userId });
    }
  }
  return results;
};

/** The playbook step that follows a hunt step, its bundle completed with the results of the runs when the step asks for them. */
export const buildHuntPlaybookResume = async (
  context: AuthContext,
  playbookContext: HuntPlaybookContext,
  runs: BasicStoreEntityHuntRun[],
): Promise<MutationPlaybookStepExecutionArgs> => {
  const bundle = JSON.parse(playbookContext.bundle) as StixBundle;
  if (playbookContext.include_results) {
    const knownIds = new Set<string>(bundle.objects.map((object) => object.id));
    bundle.objects.push(...await loadHuntRunResultsForPlaybook(context, runs, knownIds));
  }
  return {
    playbook_id: playbookContext.playbook_id,
    step_id: playbookContext.step_id,
    previous_step_id: playbookContext.previous_step_id,
    execution_id: playbookContext.execution_id,
    event_id: playbookContext.event_id,
    data_instance_id: playbookContext.data_instance_id,
    execution_start: playbookContext.execution_start,
    previous_bundle: playbookContext.previous_bundle,
    bundle: JSON.stringify(bundle),
  };
};

export const executeHuntPlaybookResume = async (context: AuthContext, step: MutationPlaybookStepExecutionArgs) => {
  // Imported lazily: the playbook manager loads the playbook components, this module included
  const { playbookStepExecution } = await import('../../manager/playbookManager/playbookManager');
  const resumed = await playbookStepExecution(context, AUTOMATION_MANAGER_USER, step);
  if (!resumed) {
    logApp.warn('[OPENCTI-MODULE] Hunt playbook step cannot be resumed, the playbook or its step does not exist anymore', {
      playbookId: step.playbook_id,
      stepId: step.step_id,
    });
  }
  return resumed;
};

export const resumeHuntPlaybookStep = async (context: AuthContext, playbookContext: HuntPlaybookContext, runs: BasicStoreEntityHuntRun[]) => {
  return executeHuntPlaybookResume(context, await buildHuntPlaybookResume(context, playbookContext, runs));
};

/**
 * Records on its playbook execution the hunt step a run handed over without the hand-over being confirmed: the platform
 * stopped while the step ran, or just before. The steps after it may have run, so it is never run again: the execution
 * shows the failure of the step instead of waiting for good.
 */
export const recordInterruptedHuntPlaybookResume = async (run: BasicStoreEntityHuntRun) => {
  if (!run.playbook_id || !run.playbook_execution_id || !run.playbook_step_id) {
    return;
  }
  const start = run.playbook_resumed_at ?? now();
  const end = now();
  const envelop = { playbook_id: run.playbook_id, playbook_execution_id: run.playbook_execution_id, last_execution_step: run.playbook_step_id } as ExecutionEnvelop;
  envelop[`step_${run.playbook_step_id}`] = {
    message: 'Hunt step interrupted while the playbook resumed, not run again',
    status: 'error',
    in_timestamp: start,
    out_timestamp: end,
    duration: new Date(end).getTime() - new Date(start).getTime(),
    error: JSON.stringify({ name: 'HuntPlaybookResumeInterrupted', message: 'The platform stopped before the hunt step confirmed it resumed: the steps after it may not have run' }, null, 2),
  };
  await redisPlaybookUpdate(envelop);
};

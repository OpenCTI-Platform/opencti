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

import * as R from 'ramda';
import type { JSONSchemaType } from 'ajv';
import type { AuthContext } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import type { StixObject } from '../../../types/stix-2-1-common';
import { logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { topEntitiesList } from '../../../database/middleware-loader';
import { elCount } from '../../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../../database/utils';
import { FilterMode, FilterOperator, OrderingMode } from '../../../generated/graphql';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../../securityPlatform/securityPlatform-types';
import { executionContext, HUNT_MANAGER_USER } from '../../../utils/access';
import { now } from '../../../utils/format';
import { playbookBundleElementsToApply, type PlaybookBundleElementsToApply, type PlaybookComponent } from '../playbook-types';
import { filterBundleElements, isBundleElementInScope } from '../playbook-utils';
import { findByIds } from '../../hunt/hunt-loaders';
import { type BasicStoreEntityHunt, ENTITY_TYPE_HUNT, HUNT_STATUS_ACTIVE, INPUT_HUNT_SOURCES, INPUT_HUNT_TARGETS, INPUT_HUNT_TECHNIQUES } from '../../hunt/hunt-types';
import { HUNT_CONFIG } from '../../hunt/hunt-utils';
import { createHuntRuns, designateHuntPlaybookLeader } from '../../hunt/huntRun/huntRun-domain';
import { withHuntLock } from '../../hunt/hunt-lock';
import { type BasicStoreEntityHuntRun, ENTITY_TYPE_HUNT_RUN, HUNT_RUN_TRIGGER_PLAYBOOK, type HuntPlaybookContext } from '../../hunt/huntRun/huntRun-types';
import { findPlaybookHuntRuns, isStorableHuntPlaybookContext, PLAYBOOK_HUNT_COMPONENT_ID, resumeHuntPlaybookStep } from '../../hunt/hunt-playbook';

export const PLAYBOOK_HUNT_MAX_HUNTS = 20;
const PLAYBOOK_HUNT_SCHEMA_MAX_OPTIONS = 500;
// A container can hold thousands of refs: the hunts referring to them are searched slice by slice to keep each filter bounded
const PLAYBOOK_HUNT_IDS_PER_QUERY = 500;

export interface HuntComponentConfiguration {
  applyToElements: PlaybookBundleElementsToApply;
  applyWithFilters?: string;
  hunt_ids: string[];
  security_platform_ids: string[];
  time_window_hours: number;
  max_hunts: number;
  wait_for_results: boolean;
  include_results: boolean;
}

const PLAYBOOK_HUNT_COMPONENT_SCHEMA: JSONSchemaType<HuntComponentConfiguration> = {
  type: 'object',
  properties: {
    applyToElements: {
      type: 'string',
      default: playbookBundleElementsToApply.onlyMain.value,
      $ref: 'Apply to',
      oneOf: [
        { const: playbookBundleElementsToApply.onlyMain.value, title: playbookBundleElementsToApply.onlyMain.title },
        { const: playbookBundleElementsToApply.allElements.value, title: playbookBundleElementsToApply.allElements.title },
        { const: playbookBundleElementsToApply.allExceptMain.value, title: playbookBundleElementsToApply.allExceptMain.title },
      ],
    },
    applyWithFilters: { type: 'string', nullable: true, default: '' },
    hunt_ids: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Hunts to run (empty: the active hunts targeting the threats, techniques and indicators of the elements)',
      items: { type: 'string', oneOf: [] },
    },
    security_platform_ids: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Security platforms (empty: the scope of each hunt)',
      items: { type: 'string', oneOf: [] },
    },
    time_window_hours: { type: 'number', default: 0, $ref: 'Time window in hours (0: the window of each hunt)' },
    max_hunts: { type: 'number', default: 10, $ref: `Maximum number of hunts per execution (up to ${PLAYBOOK_HUNT_MAX_HUNTS})` },
    wait_for_results: { type: 'boolean', default: true, $ref: 'Wait for the hunt results before continuing' },
    include_results: { type: 'boolean', default: true, $ref: 'Add the sightings and observables found to the bundle' },
  },
  required: ['applyToElements', 'hunt_ids', 'security_platform_ids', 'time_window_hours', 'max_hunts', 'wait_for_results', 'include_results'],
};

const elementRefs = (element: StixObject): string[] => {
  const container = element as StixObject & { object_refs?: string[] };
  return [element.id, ...(container.object_refs ?? [])];
};

// Least recently run first, as the search orders them: a hunt never run comes last
const byLastRunAt = (a: BasicStoreEntityHunt, b: BasicStoreEntityHunt) => {
  if (!a.last_run_at || !b.last_run_at) {
    return (a.last_run_at ? 0 : 1) - (b.last_run_at ? 0 : 1);
  }
  return new Date(a.last_run_at).getTime() - new Date(b.last_run_at).getTime();
};

/**
 * Hunts a playbook step runs: the configured hunts, or the active hunts targeting a threat, covering a technique or
 * based on an indicator / report of the elements in scope (containers bring the objects they contain).
 */
export const resolvePlaybookHunts = async (context: AuthContext, elements: StixObject[], configuration: HuntComponentConfiguration) => {
  const maxHunts = Math.min(PLAYBOOK_HUNT_MAX_HUNTS, Math.max(1, Math.round(configuration.max_hunts || 10)));
  const activeFilter = { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] };
  if ((configuration.hunt_ids ?? []).length > 0) {
    return topEntitiesList<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT], {
      first: maxHunts,
      filters: { mode: FilterMode.And, filters: [activeFilter, { key: ['id'], values: configuration.hunt_ids }], filterGroups: [] },
      withoutRels: false,
    });
  }
  const stixIds = Array.from(new Set(elements.flatMap(elementRefs)));
  if (stixIds.length === 0) {
    return [];
  }
  const knowledge = await findByIds<BasicStoreEntity>(context, HUNT_MANAGER_USER, stixIds);
  const ids = Array.from(new Set(knowledge.map((element) => element.internal_id)));
  const hunts = new Map<string, BasicStoreEntityHunt>();
  for (let start = 0; start < ids.length; start += PLAYBOOK_HUNT_IDS_PER_QUERY) {
    const slice = ids.slice(start, start + PLAYBOOK_HUNT_IDS_PER_QUERY);
    const found = await topEntitiesList<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT], {
      first: maxHunts,
      orderBy: 'last_run_at',
      orderMode: OrderingMode.Asc,
      filters: {
        mode: FilterMode.And,
        filters: [activeFilter],
        filterGroups: [{
          mode: FilterMode.Or,
          filters: [
            { key: [INPUT_HUNT_TECHNIQUES], values: slice },
            { key: [INPUT_HUNT_TARGETS], values: slice },
            { key: [INPUT_HUNT_SOURCES], values: slice },
          ],
          filterGroups: [],
        }],
      },
      // The dispatched runs carry the techniques, targets and sources of the hunts
      withoutRels: false,
    });
    found.forEach((hunt) => hunts.set(hunt.internal_id, hunt));
  }
  return Array.from(hunts.values()).sort(byLastRunAt).slice(0, maxHunts);
};

const HUNT_PLAYBOOK_DEBOUNCE_LOCK = 'hunt_playbook_debounce';

interface PlaybookHuntScope {
  playbookId: string;
  stepId: string;
  instanceId?: string | null;
}

/**
 * A playbook firing on every update of an entity must not hammer the security platforms: the same step of the same
 * playbook runs a hunt once per entity per debounce window. Any other playbook, step or entity runs it, and an
 * execution without a triggering entity (a scheduled playbook) is never skipped; the platform budgets of the hunt
 * manager bound the rest.
 */
const isRecentlyRunByPlaybook = async (context: AuthContext, hunt: BasicStoreEntityHunt, scope: PlaybookHuntScope) => {
  if (!scope.instanceId) {
    return false;
  }
  const since = new Date(Date.now() - HUNT_CONFIG.standingDebounceMinutes * 60000).toISOString();
  const count = await elCount(context, HUNT_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_HUNT_RUN],
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['hunt_id'], values: [hunt.internal_id] },
        { key: ['hunt_run_trigger'], values: [HUNT_RUN_TRIGGER_PLAYBOOK] },
        { key: ['playbook_id'], values: [scope.playbookId] },
        { key: ['playbook_step_id'], values: [scope.stepId] },
        { key: ['playbook_instance_id'], values: [scope.instanceId] },
        { key: ['created_at'], values: [since], operator: FilterOperator.Gte },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  return count > 0;
};

// The failure of a step to start its runs, read by its executor while the step continues in this process: the step
// then fails in the execution instead of continuing through out with part of its hunts, or through no-hunt, which says
// the step had no hunt to run
const huntStepStartFailures = new Map<string, unknown>();
const huntStepKey = (executionId: string, instanceId: string, stepId: string) => `${executionId}_${instanceId}_${stepId}`;

export const PLAYBOOK_HUNT_COMPONENT: PlaybookComponent<HuntComponentConfiguration> = {
  id: PLAYBOOK_HUNT_COMPONENT_ID,
  name: 'Run hunts',
  description: 'Run the hunts targeting the threats, techniques and indicators of the bundle on the security platforms, then continue with their results',
  icon: 'hunt',
  category: 'transform_and_enrich',
  is_entry_point: false,
  is_internal: false,
  ports: [{ id: 'out', type: 'out' }, { id: 'no-hunt', type: 'out' }],
  configuration_schema: PLAYBOOK_HUNT_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const [hunts, platforms] = await Promise.all([
      topEntitiesList<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT], {
        first: PLAYBOOK_HUNT_SCHEMA_MAX_OPTIONS,
        orderBy: 'name',
        orderMode: OrderingMode.Asc,
        filters: { mode: FilterMode.And, filters: [{ key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] }], filterGroups: [] },
      }),
      topEntitiesList<BasicStoreEntity>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM], {
        first: PLAYBOOK_HUNT_SCHEMA_MAX_OPTIONS,
        orderBy: 'name',
        orderMode: OrderingMode.Asc,
      }),
    ]);
    const schemaElement = {
      properties: {
        hunt_ids: { items: { oneOf: hunts.map((hunt) => ({ const: hunt.internal_id, title: hunt.name })) } },
        security_platform_ids: { items: { oneOf: platforms.map((platform) => ({ const: platform.internal_id, title: platform.name })) } },
      },
    };
    return R.mergeDeepRight<JSONSchemaType<HuntComponentConfiguration>, any>(PLAYBOOK_HUNT_COMPONENT_SCHEMA, schemaElement);
  },
  // Starts the runs; the step is resumed by the hunt manager once every run is terminated (or immediately)
  notify: async ({ executionId, eventId, playbookId, dataInstanceId, previousPlaybookNodeId, playbookNode, bundle, previousStepBundle }) => {
    const context = executionContext('playbook_components');
    const configuration = playbookNode.configuration;
    const serializedBundle = JSON.stringify(bundle);
    const playbookContext: HuntPlaybookContext = {
      playbook_id: playbookId,
      step_id: playbookNode.id,
      previous_step_id: previousPlaybookNodeId ?? playbookNode.id,
      execution_id: executionId,
      event_id: eventId,
      data_instance_id: dataInstanceId,
      execution_start: now(),
      include_results: configuration.include_results !== false,
      bundle: serializedBundle,
      previous_bundle: JSON.stringify(previousStepBundle ?? bundle),
    };
    const runs: BasicStoreEntityHuntRun[] = [];
    const waiting = configuration.wait_for_results !== false && isStorableHuntPlaybookContext(playbookContext);
    let startFailure: unknown = null;
    try {
      const inScope = bundle.objects.filter((object) => isBundleElementInScope(object, configuration.applyToElements, dataInstanceId));
      const elements = await filterBundleElements(context, inScope, configuration.applyWithFilters);
      const hunts = elements.length > 0 ? await resolvePlaybookHunts(context, elements, configuration) : [];
      for (let index = 0; index < hunts.length; index += 1) {
        const hunt = hunts[index];
        // Check and creation are serialized per hunt: concurrent executions cannot both find no recent run and both start
        // one (runs are indexed with a refresh, so the next lock holder counts the runs created here)
        const created = await withHuntLock(`${HUNT_PLAYBOOK_DEBOUNCE_LOCK}_${hunt.internal_id}`, async () => {
          if (await isRecentlyRunByPlaybook(context, hunt, { playbookId, stepId: playbookNode.id, instanceId: dataInstanceId })) {
            logApp.debug('[OPENCTI-MODULE] Playbook hunt skipped, this playbook step already ran the hunt for this entity recently', {
              huntId: hunt.internal_id,
              playbookId,
              stepId: playbookNode.id,
            });
            return [];
          }
          return createHuntRuns(context, hunt, {
            trigger: HUNT_RUN_TRIGGER_PLAYBOOK,
            securityPlatformIds: configuration.security_platform_ids ?? [],
            timeWindowHours: configuration.time_window_hours > 0 ? configuration.time_window_hours : null,
            playbook: {
              playbookId,
              executionId,
              stepId: playbookNode.id,
              instanceId: dataInstanceId,
            },
          });
        });
        runs.push(...created);
      }
      if (waiting && runs.length > 0) {
        // The continuation is handed over once every run of the step exists: the hunt manager resumes the step as soon
        // as the runs it finds are settled, and a run of the first hunt can settle before the next hunts are started
        await designateHuntPlaybookLeader(context, runs[0], playbookContext);
        return;
      }
    } catch (error) {
      logApp.error('[OPENCTI-MODULE] Playbook hunt step failed to start its runs', { cause: error, playbookId, stepId: playbookNode.id });
      // A leader designated before the failure resumes the step once its runs are settled, so resuming here as well
      // would run the next steps twice. Otherwise the step fails, even when some of its hunts started: waiting on them
      // would continue as if the others had run
      if (waiting) {
        const started = await findPlaybookHuntRuns(context, { executionId, instanceId: dataInstanceId, stepId: playbookNode.id });
        if (started.some((run) => run.playbook_leader)) {
          return;
        }
      }
      startFailure = error;
    }
    // Nothing to wait for: continue right away (the executor fails when starting the runs failed, and routes to
    // no-hunt when no run was started)
    const key = huntStepKey(executionId, dataInstanceId, playbookNode.id);
    if (startFailure) {
      huntStepStartFailures.set(key, startFailure);
    }
    try {
      await resumeHuntPlaybookStep(context, { ...playbookContext, include_results: false }, runs);
    } finally {
      huntStepStartFailures.delete(key);
    }
  },
  executor: async ({ executionId, dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const runs = await findPlaybookHuntRuns(context, { executionId, instanceId: dataInstanceId, stepId: playbookNode.id });
    const startFailure = huntStepStartFailures.get(huntStepKey(executionId, dataInstanceId, playbookNode.id));
    if (startFailure && runs.length > 0) {
      const cause = startFailure instanceof Error ? startFailure.message : String(startFailure);
      throw FunctionalError(`The step started ${runs.length} hunt run(s), then failed to start the other hunts: ${cause}`, { cause: startFailure, runIds: runs.map((run) => run.internal_id) });
    }
    if (startFailure) {
      throw startFailure;
    }
    return { output_port: runs.length > 0 ? 'out' : 'no-hunt', bundle };
  },
};

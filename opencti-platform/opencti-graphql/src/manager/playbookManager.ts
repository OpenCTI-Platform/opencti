/*
Copyright (c) 2021-2024 Filigran SAS

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
import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import type { Operation } from 'fast-json-patch';
import * as jsonpatch from 'fast-json-patch';
import moment from 'moment';
import type { Moment } from 'moment/moment';
import { createStreamProcessor, lockResource, redisPlaybookUpdate, type StreamProcessor } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { FunctionalError, TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { executionContext, RETENTION_MANAGER_USER, SYSTEM_USER } from '../utils/access';
import type { SseEvent, StreamDataEvent } from '../types/event';
import type { StixBundle } from '../types/stix-common';
import { utcDate } from '../utils/format';
import { findById } from '../modules/playbook/playbook-domain';
import { type CronConfiguration, PLAYBOOK_INTERNAL_DATA_CRON, type StreamConfiguration } from '../modules/playbook/playbook-components';
import { PLAYBOOK_COMPONENTS } from '../modules/playbook/playbook-components';
import type { BasicStoreEntityPlaybook, ComponentDefinition, PlaybookExecution, PlaybookExecutionStep } from '../modules/playbook/playbook-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { isNotEmptyField, READ_STIX_INDICES } from '../database/utils';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthContext, AuthUser } from '../types/user';
import type { MutationPlaybookStepExecutionArgs } from '../generated/graphql';
import { STIX_SPEC_VERSION } from '../database/stix';
import { getEntitiesListFromCache } from '../database/cache';
import { isStixMatchFilterGroup } from '../utils/filtering/filtering-stix/stix-filtering';
import { convertFiltersToQueryOptions } from '../utils/filtering/filtering-resolution';
import { elPaginate } from '../database/engine';
import { stixLoadById } from '../database/middleware';

const PLAYBOOK_LIVE_KEY = conf.get('playbook_manager:lock_key');
const PLAYBOOK_CRON_KEY = conf.get('playbook_manager:lock_cron_key');
const PLAYBOOK_CRON_MAX_SIZE = conf.get('playbook_manager:cron_max_size') || 500;
const STREAM_SCHEDULE_TIME = 10000;
const CRON_SCHEDULE_TIME = 60000; // 1 minute

// Only way to force the step_literal checking
// Don't try to understand, just trust
function keyStep<V>(k: `step_${string}`, v: V): { [P in `step_${string}`]: V } {
  return { [k]: v } as any; // Trust the entry checking
}
interface ExecutionEnvelopStep {
  message: string,
  previous_step_id?: string,
  status: 'success' | 'error',
  in_timestamp: string,
  out_timestamp: string,
  duration: number,
  bundle?: StixBundle | null,
  patch?: Operation[],
  error?: string,
}
export interface ExecutionEnvelop {
  playbook_id: string
  playbook_execution_id: string
  last_execution_step: string | undefined
  [k: `step_${string}`]: ExecutionEnvelopStep
}

type ObservationFn = {
  message: string,
  status: 'success' | 'error',
  executionId: string,
  playbookId: string,
  start: string,
  end: string,
  diff: number,
  previousStepId?: string,
  stepId: string,
  previousBundle?: StixBundle | null
  bundle?: StixBundle | null
  error?: string
  forceBundleTracking: boolean
};
const registerStepObservation = async (data: ObservationFn) => {
  const patch = data.previousBundle && data.bundle ? jsonpatch.compare(data.previousBundle, data.bundle) : [];
  const bundlePatch = data.previousStepId && !data.forceBundleTracking ? { patch } : { bundle: data.bundle };
  const step: ExecutionEnvelopStep = {
    message: data.message,
    status: data.status,
    previous_step_id: data.previousStepId,
    in_timestamp: data.start,
    out_timestamp: data.end,
    duration: data.diff,
    error: data.error,
    ...bundlePatch
  };
  const envelop: ExecutionEnvelop = {
    playbook_execution_id: data.executionId,
    playbook_id: data.playbookId,
    last_execution_step: data.stepId,
    ...keyStep(`step_${data.stepId}`, step)
  };
  await redisPlaybookUpdate(envelop);
};

type ExecutorFn = {
  eventId: string,
  executionId: string,
  playbookId: string,
  dataInstanceId: string,
  definition: ComponentDefinition,
  previousStep: PlaybookExecutionStep<object> | null
  nextStep: PlaybookExecutionStep<object>,
  previousStepBundle: StixBundle | null
  bundle: StixBundle
  externalCallback?: {
    externalStartDate: Date
  }
};
export const playbookExecutor = async ({
  eventId,
  executionId,
  playbookId,
  dataInstanceId,
  definition,
  previousStep,
  nextStep,
  previousStepBundle,
  bundle,
  externalCallback
} : ExecutorFn) => {
  const isExternalCallback = externalCallback !== undefined;
  const start = isExternalCallback ? externalCallback.externalStartDate : utcDate();
  const instanceWithConfig = { ...nextStep.instance, configuration: JSON.parse(nextStep.instance.configuration ?? '{}') };
  if (nextStep.component.is_internal || isExternalCallback) {
    let execution: PlaybookExecution;
    const baseBundle = structuredClone(isExternalCallback ? previousStepBundle : bundle);
    try {
      execution = await nextStep.component.executor({
        eventId,
        executionId,
        dataInstanceId,
        playbookId,
        previousPlaybookNodeId: previousStep?.instance.id,
        previousStepBundle,
        playbookNode: instanceWithConfig,
        bundle
      });
      // Execution was done correctly, log the step
      // For internal component, register directly the observability
      const end = utcDate();
      const durationDiff = end.diff(start);
      const duration = moment.duration(durationDiff);
      const observation: ObservationFn = {
        message: `${nextStep.instance.name.trim()} successfully executed in ${duration.humanize()}`,
        status: 'success',
        executionId,
        previousStepId: previousStep?.instance?.id,
        stepId: nextStep.instance.id,
        start: start.toISOString(),
        end: end.toISOString(),
        diff: durationDiff,
        playbookId,
        previousBundle: baseBundle,
        bundle: execution.bundle,
        forceBundleTracking: execution.forceBundleTracking ?? false
      };
      await registerStepObservation(observation);
    } catch (error) {
      // Error executing the step, register
      const executionError = error as Error;
      logApp.error('[OPENCTI-MODULE] Playbook manager executor error', { cause: error, manager: 'PLAYBOOK_MANAGER', step: instanceWithConfig, bundle: baseBundle });
      const end = utcDate();
      const durationDiff = end.diff(start);
      const duration = moment.duration(durationDiff);
      const logError = { message: executionError.message, stack: executionError.stack, name: executionError.name };
      const observation: ObservationFn = {
        message: `${nextStep.component.name.trim()} fail execution in ${duration.humanize()}`,
        status: 'error',
        executionId,
        previousStepId: undefined,
        stepId: nextStep.instance.id,
        start: start.toISOString(),
        end: end.toISOString(),
        diff: durationDiff,
        playbookId,
        bundle: baseBundle,
        error: JSON.stringify(logError, null, 2),
        forceBundleTracking: false
      };
      await registerStepObservation(observation);
      return;
    }
    // Send the result to the next component if needed
    if (execution.output_port) {
      // Find the next op for this attachment
      const connections = definition.links.filter((c) => c.from.id === nextStep.instance.id && c.from.port === execution.output_port);
      for (let connectionIndex = 0; connectionIndex < connections.length; connectionIndex += 1) {
        const connection = connections[connectionIndex];
        const nextInstance = definition.nodes.find((c) => c.id === connection.to.id);
        const fromInstance = definition.nodes.find((c) => c.id === connection.from.id);
        if (!nextInstance || !fromInstance) {
          throw UnsupportedError('Invalid playbook, nextInstance needed');
        }
        const fromConnector = PLAYBOOK_COMPONENTS[fromInstance.component_id];
        const nextConnector = PLAYBOOK_COMPONENTS[nextInstance.component_id];
        await playbookExecutor({
          eventId,
          executionId,
          playbookId,
          dataInstanceId,
          definition,
          previousStep: { component: fromConnector, instance: fromInstance },
          nextStep: { component: nextConnector, instance: nextInstance },
          previousStepBundle,
          bundle: execution.bundle
        });
      }
    }
  } else {
    if (!nextStep.component.notify) {
      throw UnsupportedError('Notify definition is required');
    }
    // Component must rely on an external call.
    // Execution will be continued through an external API call
    try {
      await nextStep.component.notify({
        eventId,
        executionId,
        dataInstanceId,
        playbookId,
        previousPlaybookNodeId: previousStep?.instance.id,
        playbookNode: instanceWithConfig,
        previousStepBundle,
        bundle
      });
    } catch (notifyError) {
      // For now any problem sending in notification will not be tracked
    }
  }
};

const playbookStreamHandler = async (streamEvents: Array<SseEvent<StreamDataEvent>>) => {
  try {
    if (streamEvents.length === 0) {
      return;
    }
    const context = executionContext('playbook_manager');
    const playbooks = await getEntitiesListFromCache<BasicStoreEntityPlaybook>(context, SYSTEM_USER, ENTITY_TYPE_PLAYBOOK);
    for (let index = 0; index < streamEvents.length; index += 1) {
      const streamEvent = streamEvents[index];
      const { id: eventId, data: { data, type, origin } } = streamEvent;
      // For each event we need to check ifs
      for (let playbookIndex = 0; playbookIndex < playbooks.length; playbookIndex += 1) {
        const playbook = playbooks[playbookIndex];
        // Execute only of definition is available
        if (playbook.playbook_definition) {
          // Execute only if event coming from different playbook
          if (origin.playbook_id !== playbook.internal_id) {
            const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
            // 01. Find the starting point of the playbook
            const instance = def.nodes.find((n) => n.id === playbook.playbook_start);
            if (instance && instance.component_id === 'PLAYBOOK_INTERNAL_DATA_STREAM') {
              const connector = PLAYBOOK_COMPONENTS[instance.component_id];
              const { update, create, delete: deletion, filters } = (JSON.parse(instance.configuration ?? '{}') as StreamConfiguration);
              const jsonFilters = filters ? JSON.parse(filters) : null;
              let validEventType = false;
              if (type === 'create' && create === true) validEventType = true;
              if (type === 'update' && update === true) validEventType = true;
              if (type === 'delete' && deletion === true) validEventType = true;
              const isMatch = await isStixMatchFilterGroup(context, SYSTEM_USER, data, jsonFilters);
              // 02. Execute the component
              if (validEventType && isMatch) {
                const nextStep = { component: connector, instance };
                const bundle: StixBundle = {
                  id: uuidv4(),
                  spec_version: STIX_SPEC_VERSION,
                  type: 'bundle',
                  objects: [data]
                };
                await playbookExecutor({
                  eventId,
                  // Basic
                  executionId: uuidv4(),
                  playbookId: playbook.id,
                  dataInstanceId: data.id,
                  definition: def,
                  // Steps
                  previousStep: null,
                  nextStep,
                  // Data
                  previousStepBundle: null,
                  bundle,
                });
              }
            }
          }
        }
      }
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] Playbook manager stream error', { cause: e, manager: 'PLAYBOOK_MANAGER' });
  }
};

export const executePlaybookOnEntity = async (context: AuthContext, id: string, entityId: string) => {
  const playbooks = await getEntitiesListFromCache<BasicStoreEntityPlaybook>(context, SYSTEM_USER, ENTITY_TYPE_PLAYBOOK);
  let playbook = null;
  const filteredPlaybooks = playbooks.filter((n) => n.id === id);
  if (filteredPlaybooks.length > 0) {
    playbook = filteredPlaybooks.at(0);
  } else {
    throw FunctionalError('Playbook does not exist', { id });
  }
  // Execute only of definition is available
  if (playbook && playbook.playbook_definition) {
    const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
    const instance = def.nodes.find((n) => n.id === playbook.playbook_start);
    if (instance) {
      const connector = PLAYBOOK_COMPONENTS[instance.component_id];
      const data = await stixLoadById(context, RETENTION_MANAGER_USER, entityId);
      if (data) {
        try {
          const eventId = `${utcDate().toDate().getTime()}-0`;
          const nextStep = { component: connector, instance };
          const bundle: StixBundle = {
            id: uuidv4(),
            spec_version: STIX_SPEC_VERSION,
            type: 'bundle',
            objects: [data]
          };
          playbookExecutor({
            eventId,
            // Basic
            executionId: uuidv4(),
            playbookId: playbook.id,
            dataInstanceId: data.id,
            definition: def,
            // Steps
            previousStep: null,
            nextStep,
            // Data
            previousStepBundle: null,
            bundle,
          }).catch((err) => {
            logApp.error('[OPENCTI-MODULE] Playbook manager step executor error', { cause: err, id: entityId, manager: 'PLAYBOOK_MANAGER' });
          });
          return true;
        } catch (e) {
          logApp.error('[OPENCTI-MODULE] Playbook manager step executor error', { cause: e, id: entityId, manager: 'PLAYBOOK_MANAGER' });
          return false;
        }
      }
    }
  }
  return false;
};

const initPlaybookManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let streamScheduler: SetIntervalAsyncTimer<[]>;
  let cronScheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let running = false;
  let shutdown = false;
  const wait = (ms: number) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };
  const playbookHandler = async () => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([PLAYBOOK_LIVE_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-MODULE] Running playbook manager');
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'Playbook manager', playbookStreamHandler);
      await streamProcessor.start('live');
      while (!shutdown && streamProcessor.running()) {
        lock.signal.throwIfAborted();
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of playbook manager processing');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Playbook manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Playbook manager error', { cause: e, manager: 'PLAYBOOK_MANAGER' });
      }
    } finally {
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };
  const shouldTriggerNow = (cronConfiguration: CronConfiguration, baseDate: Moment): boolean => {
    const now = baseDate.clone().startOf('minutes'); // 2022-11-25T19:11:00.000Z
    const { triggerTime } = cronConfiguration;
    switch (cronConfiguration.period) {
      case 'minute': {
        // Need to check if time is aligned on the perfect hour
        const nowMinuteAlign = now.clone().startOf('minutes');
        return now.isSame(nowMinuteAlign);
      }
      case 'hour': {
        // Need to check if time is aligned on the perfect hour
        const nowHourAlign = now.clone().startOf('hours');
        return now.isSame(nowHourAlign);
      }
      case 'day': {
        // Need to check if time is aligned on the day hour (like 19:11:00.000Z)
        const dayTime = `${now.clone().format('HH:mm:ss.SSS')}Z`;
        return triggerTime === dayTime;
      }
      case 'week': {
        // Need to check if time is aligned on the week hour (like 1-19:11:00.000Z)
        // 1 being Monday and 7 being Sunday.
        const weekTime = `${now.clone().isoWeekday()}-${now.clone().format('HH:mm:ss.SSS')}Z`;
        return triggerTime === weekTime;
      }
      case 'month': {
        // Need to check if time is aligned on the month hour (like 22-19:11:00.000Z)
        const monthTime = `${now.clone().date()}-${now.clone().format('HH:mm:ss.SSS')}Z`;
        return triggerTime === monthTime;
      }
      default:
        return false;
    }
  };
  const handlePlaybookCrons = async (context: AuthContext) => {
    const baseDate = utcDate().startOf('minutes');
    // Get playbook crons that need to be executed
    const playbooks = await getEntitiesListFromCache<BasicStoreEntityPlaybook>(context, SYSTEM_USER, ENTITY_TYPE_PLAYBOOK);
    for (let playbookIndex = 0; playbookIndex < playbooks.length; playbookIndex += 1) {
      const playbook = playbooks[playbookIndex];
      // Execute only of definition is available
      if (playbook.playbook_definition) {
        // Execute only if event coming from different playbook
        const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
        // 01. Find the starting point of the playbook
        const instance = def.nodes.find((n) => n.id === playbook.playbook_start);
        if (instance && instance.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id) {
          const connector = PLAYBOOK_COMPONENTS[instance.component_id];
          const cronConfiguration = (JSON.parse(instance.configuration ?? '{}') as CronConfiguration);
          if (shouldTriggerNow(cronConfiguration, baseDate) && cronConfiguration.filters) {
            logApp.info(`[OPENCTI-MODULE] Running playbook ${instance.name} for cron ${cronConfiguration.period} (${cronConfiguration.triggerTime})`);
            const jsonFilters = JSON.parse(cronConfiguration.filters);
            let conversionOpts = {};
            if (cronConfiguration.onlyLast) {
              const fromDate = baseDate.clone().subtract(1, cronConfiguration.period).toDate();
              conversionOpts = { ...conversionOpts, after: fromDate };
            }
            const queryOptions = await convertFiltersToQueryOptions(jsonFilters, conversionOpts);
            const opts = { ...queryOptions, first: PLAYBOOK_CRON_MAX_SIZE };
            const result = await elPaginate(context, RETENTION_MANAGER_USER, READ_STIX_INDICES, opts);
            const elements = result.edges;
            logApp.info(`[OPENCTI-MODULE] Running playbook ${instance.name} on ${elements.length} elements`);
            for (let index = 0; index < elements.length; index += 1) {
              const { node } = elements[index];
              const data = await stixLoadById(context, RETENTION_MANAGER_USER, node.internal_id);
              if (data) {
                try {
                  const eventId = `${utcDate().toDate().getTime()}-${index}`;
                  const nextStep = { component: connector, instance };
                  const bundle: StixBundle = {
                    id: uuidv4(),
                    spec_version: STIX_SPEC_VERSION,
                    type: 'bundle',
                    objects: [data]
                  };
                  await playbookExecutor({
                    eventId,
                    // Basic
                    executionId: uuidv4(),
                    playbookId: playbook.id,
                    dataInstanceId: data.id,
                    definition: def,
                    // Steps
                    previousStep: null,
                    nextStep,
                    // Data
                    previousStepBundle: null,
                    bundle,
                  });
                } catch (e) {
                  logApp.error('[OPENCTI-MODULE] Playbook manager cron error', { cause: e, id: node.id, manager: 'PLAYBOOK_MANAGER' });
                }
              }
            }
          }
        }
      }
    }
  };
  const PlaybookCronHandler = async () => {
    const context = executionContext('playbook_manager');
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([PLAYBOOK_CRON_KEY], { retryCount: 0 });
      logApp.info('[OPENCTI-MODULE] Running playbook manager (cron)');
      while (!shutdown) {
        lock.signal.throwIfAborted();
        await handlePlaybookCrons(context);
        await wait(CRON_SCHEDULE_TIME);
      }
      logApp.info('[OPENCTI-MODULE] End of playbook manager processing (cron)');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Playbook manager (cron) already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Playbook manager cron handler error', { cause: e, manager: 'PLAYBOOK_MANAGER' });
      }
    } finally {
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      streamScheduler = setIntervalAsync(async () => {
        await playbookHandler();
      }, STREAM_SCHEDULE_TIME);
      cronScheduler = setIntervalAsync(async () => {
        await PlaybookCronHandler();
      }, CRON_SCHEDULE_TIME);
    },
    status: (settings?: BasicStoreSettings) => {
      return {
        id: 'PLAYBOOK_MANAGER',
        enable: isNotEmptyField(settings?.enterprise_edition) && booleanConf('playbook_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping playbook manager');
      shutdown = true;
      if (streamScheduler) await clearIntervalAsync(streamScheduler);
      if (cronScheduler) await clearIntervalAsync(cronScheduler);
      return true;
    },
  };
};

export const playbookStepExecution = async (context: AuthContext, user: AuthUser, args: MutationPlaybookStepExecutionArgs) => {
  const playbook = await findById(context, user, args.playbook_id);
  if (!playbook) {
    return false;
  }
  const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const nextInstance = def.nodes.find((n) => n.id === args.step_id);
  const previousInstance = def.nodes.find((n) => n.id === args.previous_step_id);
  if (!nextInstance || !previousInstance) {
    return false;
  }
  const connector = PLAYBOOK_COMPONENTS[nextInstance.component_id];
  // 02. Execute the component
  const nextStep = { component: connector, instance: nextInstance };
  const previousStep = { component: connector, instance: previousInstance };
  // const previousData = JSON.parse(args.previous_data);
  const bundle = JSON.parse(args.bundle) as StixBundle;
  return playbookExecutor({
    eventId: args.event_id,
    executionId: args.execution_id,
    playbookId: args.playbook_id,
    dataInstanceId: args.data_instance_id,
    definition: def,
    previousStep,
    nextStep,
    previousStepBundle: JSON.parse(args.previous_bundle),
    bundle,
    externalCallback: {
      externalStartDate: args.execution_start,
    }
  }).then(() => true);
};

const playbookManager = initPlaybookManager();

export default playbookManager;

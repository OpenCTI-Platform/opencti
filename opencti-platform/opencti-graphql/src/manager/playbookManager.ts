/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { v4 as uuidv4 } from 'uuid';
import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { createStreamProcessor, lockResource, redisPlaybookUpdate, type StreamProcessor } from '../database/redis';
import conf, { booleanConf, logApp } from '../config/conf';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { DataEvent, SseEvent } from '../types/event';
import type { StixCoreObject } from '../types/stix-common';
// import { loadConnectorById } from '../domain/connector';
// import { pushToConnector } from '../database/rabbitmq';
import { now } from '../utils/format';
import { findAllPlaybooks } from '../modules/playbook/playbook-domain';
import { PLAYBOOK_COMPONENTS } from '../modules/playbook/playbook-components';
import type {
  ComponentDefinition, NodeInstance,
  PlaybookComponent,
  PlaybookComponentConfiguration
} from '../modules/playbook/playbook-types';
import { isNotEmptyField } from '../database/utils';
import type { BasicStoreSettings } from '../types/settings';

const PLAYBOOK_LIVE_KEY = conf.get('playbook_manager:lock_key');
const STREAM_SCHEDULE_TIME = 10000;

export interface ExecutionEnvelop {
  playbook_run_id: string
  last_execution_step: string | undefined
  [k: `step_${string}`]: {
    // Setup when sending
    in_timestamp: string,
    out_timestamp: string,
    output_port: string | undefined,
    data: StixCoreObject,
    error?: string
  }
}

/*
const PLAYBOOKS: PlayBookSchema[] = [
  {
    id: uuidv4(),
    name: 'playbook01',
    description: 'description',
    playbook_start: 'stream',
    playbook_variables: [],
    playbook_definition: {
      nodes: [
        {
          id: 'stream',
          component_id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
          configuration: {}
        },
        {
          id: 'filter',
          component_id: 'PLAYBOOK_FILTERING_COMPONENT',
          configuration: {
            filters: JSON.stringify({ entity_type: [{ id: 'Report', value: 'Rapport' }] }),
          }
        },
        {
          id: 'console',
          component_id: 'PLAYBOOK_CONSOLE_STANDARD_COMPONENT',
          configuration: {}
        },
        {
          id: 'error',
          component_id: 'PLAYBOOK_CONSOLE_ERROR_COMPONENT',
          configuration: {}
        }
      ],
      links: [
        { // connection from stream to filtering
          from: { id: 'stream', port: 'out' },
          to: { id: 'filter' },
        },
        { // connection from filtering to console on empty
          from: { port: 'empty', id: 'filter' },
          to: { id: 'error' },
        },
        { // connection from filtering to console on standard
          from: { port: 'out', id: 'filter' },
          to: { id: 'console' },
        }
      ]
    }
  }
];
*/

type ObservationFn = {
  playbookRunId: string,
  start: string,
  end: string,
  stepId: string,
  data: StixCoreObject
  error?: string
};
const registerObservation = async ({ playbookRunId, start, end, stepId, data, error } : ObservationFn) => {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const envelop: ExecutionEnvelop = {
    playbook_run_id: playbookRunId,
    last_execution_step: stepId,
    [`step_${stepId}`]: { in_timestamp: start, out_timestamp: end, data, error }
  };
  await redisPlaybookUpdate(envelop);
};

const playbookExecutor = async (
  playbookRunId: string,
  definition: ComponentDefinition,
  component: PlaybookComponent<PlaybookComponentConfiguration>,
  instance: NodeInstance<PlaybookComponentConfiguration>,
  data: StixCoreObject
) => {
  const start = now();
  try {
    const execution = await component.executor({ playbookRunId, instance, data });
    // For internal component, register directly the observability
    if (component.is_internal) {
      const observation = { stepId: instance.id, start, end: now(), playbookRunId, data };
      await registerObservation(observation);
    }
    // Send the result to the next component if needed
    if (execution.output_port) {
      // Find the next op for this attachment
      const connections = definition.links.filter((c) => c.from.id === instance.id && c.from.port === execution.output_port);
      for (let connectionIndex = 0; connectionIndex < connections.length; connectionIndex += 1) {
        const connection = connections[connectionIndex];
        const nextInstance = definition.nodes.find((c) => c.id === connection.to.id);
        if (!nextInstance) {
          throw UnsupportedError('Invalid playbook, nextInstance needed');
        }
        const nextConnector = PLAYBOOK_COMPONENTS[nextInstance.component_id];
        await playbookExecutor(playbookRunId, definition, nextConnector, nextInstance, execution.data);
      }
    }
  } catch (e) {
    const observation = { stepId: instance.id, start, end: now(), playbookRunId, data, error: JSON.stringify(e) };
    await registerObservation(observation);
  }
};

const playbookStreamHandler = async (streamEvents: Array<SseEvent<DataEvent>>) => {
  try {
    if (streamEvents.length === 0) {
      return;
    }
    const context = executionContext('playbook_manager');
    const opts = { /* filters: [{ key: 'playbook_running', values: [true] }], */ connectionFormat: false };
    const playbooks = await findAllPlaybooks(context, SYSTEM_USER, opts);
    // TODO need to be filter by INTERNAL_DATA_STREAM entry point
    for (let index = 0; index < streamEvents.length; index += 1) {
      const streamEvent = streamEvents[index];
      const { data: { data } } = streamEvent;
      // For each event we need to check ifs
      for (let playbookIndex = 0; playbookIndex < playbooks.length; playbookIndex += 1) {
        const playbook = playbooks[playbookIndex];
        if (playbook.playbook_definition) {
          const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
          // 01. Find the starting point of the playbook
          const instance = def.nodes.find((n) => n.id === playbook.playbook_start);
          if (!instance) {
            throw UnsupportedError('Invalid playbook, entry point needed');
          }
          const connector = PLAYBOOK_COMPONENTS[instance.component_id];
          // 02. Execute the component
          const playbookRunId = uuidv4();
          await playbookExecutor(playbookRunId, def, connector, instance, data);
        }
      }
    }
  } catch (e) {
    logApp.error('[OPENCTI-MODULE] Error executing playbook manager', { error: e });
  }
};

const initPlaybookManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let streamScheduler: SetIntervalAsyncTimer<[]>;
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
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of playbook manager processing');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Playbook manager already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Playbook manager failed to start', { error: e });
      }
    } finally {
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      streamScheduler = setIntervalAsync(async () => {
        await playbookHandler();
      }, STREAM_SCHEDULE_TIME);
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
      return true;
    },
  };
};
const playbookManager = initPlaybookManager();

export default playbookManager;

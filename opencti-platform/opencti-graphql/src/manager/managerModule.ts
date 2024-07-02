import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import moment from 'moment/moment';
import { createStreamProcessor, lockResource, type StreamProcessor } from '../database/redis';
import type { BasicStoreSettings } from '../types/settings';
import { logApp } from '../config/conf';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { SYSTEM_USER } from '../utils/access';
import { utcDate } from '../utils/format';
import { wait } from '../database/utils';

export interface HandlerInput {
  shutdown?: () => Promise<void>
}

export interface ManagerCronScheduler {
  handler: (input?: any) => Promise<void>
  interval: number
  lockKey: string
  infiniteInterval?: number
  handlerInitializer?: () => Promise<HandlerInput>
}

export interface ManagerStreamScheduler {
  handler: () => void;
  interval: number;
  lockKey: string;
  streamOpts?: { withInternal: boolean, streamName: string };
  streamProcessorStartFrom: () => string;
}

export interface ManagerDefinition {
  id: string;
  label: string;
  executionContext: string;
  cronSchedulerHandler?: ManagerCronScheduler;
  streamSchedulerHandler?: ManagerStreamScheduler;
  enabledByConfig: boolean;
  enabled: (settings?: BasicStoreSettings) => boolean; // enabled from configuration and settings
  enabledToStart: () => boolean; // if manager can be started (some managers need to start even when disabled)
  enterpriseEditionOnly?: boolean;
  warning?: () => boolean; // condition to display a warning on manager module (ex: missing configuration, manager can't start)
}

const initManager = (manager: ManagerDefinition) => {
  const WAIT_TIME_ACTION = 2000;
  let scheduler: SetIntervalAsyncTimer<[]>;
  let streamScheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let running = false;
  let shutdown = false;

  const cronHandler = async (cronInputFn?: () => Promise<HandlerInput>) => {
    if (manager.cronSchedulerHandler) {
      let lock;
      let cronInput;
      const startDate = utcDate();
      try {
        // date
        // Lock the manager
        lock = await lockResource([manager.cronSchedulerHandler.lockKey], { retryCount: 0 });
        running = true;
        cronInput = cronInputFn ? await cronInputFn() : undefined;
        if (manager.cronSchedulerHandler.infiniteInterval) {
          logApp.info(`[OPENCTI-MODULE] Running ${manager.label} infinite cron handler`);
          while (!shutdown) {
            await manager.cronSchedulerHandler.handler(cronInput);
            await wait(manager.cronSchedulerHandler.infiniteInterval);
          }
        } else {
          await manager.cronSchedulerHandler.handler(cronInput);
        }
      } catch (e: any) {
        if (e.extensions.name === TYPE_LOCK_ERROR) {
          logApp.debug(`[OPENCTI-MODULE] ${manager.label} already started by another API`);
        } else {
          logApp.error(e, { manager: manager.id });
        }
      } finally {
        running = false;
        if (lock) await lock.unlock();
        if (cronInput && cronInput.shutdown) await cronInput.shutdown();
        if (startDate) {
          const duration = moment.duration(utcDate().diff(startDate)).asMilliseconds();
          logApp.debug(`[OPENCTI-MODULE] ${manager.label} done in ${duration}ms`);
        }
      }
    }
  };

  const streamHandler = async () => {
    if (manager.streamSchedulerHandler) {
      let lock;
      try {
      // Lock the manager
        lock = await lockResource([manager.streamSchedulerHandler.lockKey], { retryCount: 0 });
        running = true;
        logApp.info(`[OPENCTI-MODULE] Running ${manager.label} stream handler`);
        streamProcessor = createStreamProcessor(SYSTEM_USER, 'File index manager', manager.streamSchedulerHandler.handler, manager.streamSchedulerHandler.streamOpts);
        const startFrom = manager.streamSchedulerHandler.streamProcessorStartFrom();
        await streamProcessor.start(startFrom);
        while (!shutdown && streamProcessor.running()) {
          lock.signal.throwIfAborted();
          await wait(WAIT_TIME_ACTION);
        }
        logApp.info(`[OPENCTI-MODULE] End of ${manager.label} stream handler`);
      } catch (e: any) {
        if (e.extensions.name === TYPE_LOCK_ERROR) {
          logApp.debug(`[OPENCTI-MODULE] ${manager.label} stream handler already started by another API`);
        } else {
          logApp.error(e, { manager: manager.id });
        }
      } finally {
        if (streamProcessor) await streamProcessor.shutdown();
        if (lock) await lock.unlock();
      }
    }
  };

  return {
    manager,
    start: async () => {
      logApp.info(`[OPENCTI-MODULE] Starting ${manager.label}`);
      if (manager.cronSchedulerHandler) {
        const { handlerInitializer } = manager.cronSchedulerHandler;
        scheduler = setIntervalAsync(async () => {
          await cronHandler(handlerInitializer);
        }, manager.cronSchedulerHandler.interval);
      }
      if (manager.streamSchedulerHandler) {
        streamScheduler = setIntervalAsync(async () => {
          await streamHandler();
        }, manager.streamSchedulerHandler.interval);
      }
    },
    status: (settings?: BasicStoreSettings) => {
      return {
        id: manager.id,
        enable: manager.enabled(settings),
        running,
        warning: manager.warning?.() || false,
      };
    },
    shutdown: async () => {
      logApp.info(`[OPENCTI-MODULE] Stopping ${manager.label}`);
      shutdown = true;
      if (scheduler) await clearIntervalAsync(scheduler);
      if (streamScheduler) await clearIntervalAsync(streamScheduler);
      return true;
    },
  };
};

interface ManagerModule {
  manager: ManagerDefinition;
  start: () => Promise<void>;
  shutdown: () => Promise<boolean>;
  status: (settings?: BasicStoreSettings) => { running: boolean, enable: boolean, warning: boolean, id: string };
}

const managersModule = {
  managers: [] as ManagerModule[],

  add(managerModule: ManagerModule) {
    this.managers.push(managerModule);
  },
};

export const registerManager = (manager: ManagerDefinition) => {
  const managerModule = initManager(manager);
  managersModule.add(managerModule);
};

export const startAllManagers = async () => {
  for (let i = 0; i < managersModule.managers.length; i += 1) {
    const managerModule = managersModule.managers[i];
    if (managerModule.manager.enabledToStart()) {
      await managerModule.start();
    } else {
      logApp.info(`[OPENCTI-MODULE] ${managerModule.manager.label} not started (disabled by configuration)`);
    }
  }
};

export const shutdownAllManagers = async () => {
  for (let i = 0; i < managersModule.managers.length; i += 1) {
    const managerModule = managersModule.managers[i];
    if (managerModule.manager.enabledToStart()) {
      await managerModule.shutdown();
    }
  }
};

export const getAllManagersStatuses = (settings?: BasicStoreSettings) => {
  return [...managersModule.managers.map((module) => module.status(settings))];
};

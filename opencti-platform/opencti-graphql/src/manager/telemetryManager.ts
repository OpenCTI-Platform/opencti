import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import conf, { booleanConf, logApp } from '../config/conf';
import { createStreamProcessor, lockResource, type StreamProcessor } from '../database/redis';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { isNotEmptyField } from '../database/utils';
import type { Settings } from '../generated/graphql';
import { getSettings } from '../domain/settings';
import { filigranTelemetryManager } from '../config/filigranTelemetry';

const TELEMETRY_KEY = conf.get('telemetry_manager:lock_key');
const SCHEDULE_TIME = 10000;

const telemetryStreamHandler = async () => {
  try {
    const context = executionContext('telemetry_manager');
    const settings = await getSettings(context) as Settings;
    const enabledModules = settings.platform_modules?.map((module) => (module.enable ? module.id : null))
      .filter((n) => n) as string[];
    const runningModules = settings.platform_modules?.map((module) => (module.running ? module.id : null))
      .filter((n) => n) as string[];
    filigranTelemetryManager.setLanguage(settings.platform_language ?? 'undefined');
    filigranTelemetryManager.setIsEEActivated(isNotEmptyField(settings.enterprise_edition));
    filigranTelemetryManager.setEEActivationDate(settings.enterprise_edition);
    filigranTelemetryManager.setNumberOfInstances(settings.platform_cluster.instances_number);
    filigranTelemetryManager.registerFiligranTelemetry();
  } catch (e) {
    logApp.error(e, { manager: 'TELEMETRY_MANAGER' });
  }
};

const initTelemetryManager = () => {
  const WAIT_TIME_ACTION = 1000;
  let scheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let running = false;
  let shutdown = false;
  const wait = (ms: number) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };

  const telemetryHandler = async () => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([TELEMETRY_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-MODULE] Running telemetry manager');
      streamProcessor = createStreamProcessor(SYSTEM_USER, 'Telemetry manager', telemetryStreamHandler);
      await streamProcessor.start('live');
      while (!shutdown && streamProcessor.running()) {
        lock.signal.throwIfAborted();
        await wait(WAIT_TIME_ACTION);
      }
      logApp.info('[OPENCTI-MODULE] End of telemetry manager processing');
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Telemetry manager already started by another API');
      } else {
        logApp.error(e, { manager: 'TELEMETRY_MANAGER' });
      }
    } finally {
      running = false;
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };

  return {
    start: async () => {
      // Start the listening of events
      scheduler = setIntervalAsync(async () => {
        await telemetryHandler();
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'TELEMETRY_MANAGER',
        enable: booleanConf('telemetry_manager:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping telemetry manager');
      shutdown = true;
      if (scheduler) {
        await clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const telemetryManager = initTelemetryManager();

export default telemetryManager;

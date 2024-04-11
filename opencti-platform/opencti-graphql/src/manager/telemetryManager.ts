import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import conf, { booleanConf, logApp } from '../config/conf';
import { lockResource } from '../database/redis';
import { executionContext } from '../utils/access';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { isNotEmptyField } from '../database/utils';
import type { Settings } from '../generated/graphql';
import { getSettings } from '../domain/settings';
import { filigranTelemetryManager } from '../config/filigranTelemetry';
import { usersWithActiveSession } from '../database/session';

const TELEMETRY_KEY = conf.get('telemetry_manager:lock_key');
const SCHEDULE_TIME = 10000;

const fetchTelemetryData = async () => {
  try {
    const context = executionContext('telemetry_manager');
    const timestamp = new Date().getTime();
    // Fetch settings
    const settings = await getSettings(context) as Settings;
    const enabledModules = settings.platform_modules?.map((module) => (module.enable ? module.id : null))
      .filter((n) => n) as string[];
    const runningModules = settings.platform_modules?.map((module) => (module.running ? module.id : null))
      .filter((n) => n) as string[];
    // Set filigranTelemetryManager settings telemetry data
    filigranTelemetryManager.setLanguage(settings.platform_language ?? 'undefined');
    filigranTelemetryManager.setIsEEActivated(isNotEmptyField(settings.enterprise_edition));
    filigranTelemetryManager.setEEActivationDate(settings.enterprise_edition);
    filigranTelemetryManager.setNumberOfInstances(settings.platform_cluster.instances_number);
    // Register filigran telemetry data
    filigranTelemetryManager.registerFiligranTelemetry(timestamp);
    // Get number of active users over time
    const activUsers = await usersWithActiveSession();
    filigranTelemetryManager.setActivUsers(activUsers, timestamp);
  } catch (e) {
    logApp.error(e, { manager: 'TELEMETRY_MANAGER' });
  }
};

const initTelemetryManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  let running = false;

  const telemetryHandler = async () => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([TELEMETRY_KEY], { retryCount: 0 });
      running = true;
      logApp.info('[OPENCTI-MODULE] Running telemetry manager');
      await fetchTelemetryData();
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.debug('[OPENCTI-MODULE] Telemetry manager already started by another API');
      } else {
        logApp.error(e, { manager: 'TELEMETRY_MANAGER' });
      }
    } finally {
      running = false;
      logApp.debug('[OPENCTI-MODULE] Telemetry manager done');
      if (lock) await lock.unlock();
    }
  };

  return {
    start: async () => {
      // Fetch data periodically
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
      if (scheduler) {
        await clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const telemetryManager = initTelemetryManager();

export default telemetryManager;

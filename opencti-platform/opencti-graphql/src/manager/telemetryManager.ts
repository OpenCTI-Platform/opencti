import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { ConsoleMetricExporter, MeterProvider, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { Resource } from '@opentelemetry/resources';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import nconf from 'nconf';
import conf, { booleanConf, ENABLED_TELEMETRY, logApp, PLATFORM_VERSION } from '../config/conf';
import { lockResource } from '../database/redis';
import { executionContext } from '../utils/access';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { isNotEmptyField } from '../database/utils';
import type { Settings } from '../generated/graphql';
import { getSettings } from '../domain/settings';
import { usersWithActiveSession } from '../database/session';
import { TELEMETRY_SERVICE_NAME, TelemetryMeterManager } from '../config/TelemetryMeterManager';

const TELEMETRY_KEY = conf.get('telemetry_manager:lock_key');
const SCHEDULE_TIME = 100000; // record telemetry data period
const EXPORT_INTERVAL = 100000; // TODO set to 1 per day

const createFiligranTelemetryMeterManager = () => {
  // ------- Telemetry // TODO telemetry service, wrap methods in the service
  let resource = Resource.default();
  const filigranMetricReaders = [];
  if (ENABLED_TELEMETRY) {
    // -- Resource
    const filigranResource = new Resource({
      [SEMRESATTRS_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
      [SEMRESATTRS_SERVICE_VERSION]: PLATFORM_VERSION,
    });
    resource = resource.merge(filigranResource);
    // -- Readers with exporter
    // Console Exporter
    const readerWithConsoleExporter = new PeriodicExportingMetricReader({
      exporter: new ConsoleMetricExporter(),
      exportIntervalMillis: EXPORT_INTERVAL,
    });
    filigranMetricReaders.push(readerWithConsoleExporter);
    // OTLP Exporter
    const otlpUri = nconf.get('app:telemetry:filigran:exporter_otlp');
    if (isNotEmptyField(otlpUri)) {
      const readerWithOtlpExporter = new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter({ url: otlpUri }),
        exportIntervalMillis: EXPORT_INTERVAL,
      });
      filigranMetricReaders.push(readerWithOtlpExporter);
    }
  }
  const filigranMeterProvider = new MeterProvider(({
    resource,
    readers: filigranMetricReaders,
  }));

  const filigranTelemetryMeterManager = new TelemetryMeterManager(filigranMeterProvider);
  filigranTelemetryMeterManager.registerFiligranTelemetry();
  return filigranTelemetryMeterManager;
};

const fetchTelemetryData = async (filigranTelemetryMeterManager: TelemetryMeterManager) => {
  try {
    const context = executionContext('telemetry_manager');
    // Fetch settings
    const settings = await getSettings(context) as Settings;
    // Set filigranTelemetryManager settings telemetry data
    filigranTelemetryMeterManager.setLanguage(settings.platform_language ?? 'undefined');
    filigranTelemetryMeterManager.setIsEEActivated(isNotEmptyField(settings.enterprise_edition) ? 1 : 0);
    filigranTelemetryMeterManager.setEEActivationDate(settings.enterprise_edition);
    filigranTelemetryMeterManager.setNumberOfInstances(settings.platform_cluster.instances_number);
    // Get number of active users since fetchTelemetryData() last execution
    const activUsers = await usersWithActiveSession(SCHEDULE_TIME / 1000 / 60);
    filigranTelemetryMeterManager.setActivUsers(activUsers, new Date().getTime());
  } catch (e) {
    logApp.error(e, { manager: 'TELEMETRY_MANAGER' });
  }
};

const initTelemetryManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  let running = false;

  const telemetryHandler = async (filigranTelemetryMeterManager: TelemetryMeterManager) => {
    logApp.info('[OPENCTI-MODULE] Running telemetry manager');
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([TELEMETRY_KEY], { retryCount: 0 });
      running = true;
      await fetchTelemetryData(filigranTelemetryMeterManager);
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
      const filigranTelemetryMeterManager = createFiligranTelemetryMeterManager();
      // Fetch data periodically
      scheduler = setIntervalAsync(async () => {
        await telemetryHandler(filigranTelemetryMeterManager);
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

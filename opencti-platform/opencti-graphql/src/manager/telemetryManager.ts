import { Resource } from '@opentelemetry/resources';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { SEMRESATTRS_SERVICE_INSTANCE_ID } from '@opentelemetry/semantic-conventions/build/src/resource/SemanticResourceAttributes';
import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { AggregationTemporality } from '@opentelemetry/sdk-metrics/build/src/export/AggregationTemporality';
import conf, { logApp, PLATFORM_VERSION } from '../config/conf';
import { executionContext, TELEMETRY_MANAGER_USER } from '../utils/access';
import { isNotEmptyField } from '../database/utils';
import type { Settings } from '../generated/graphql';
import { getClusterInformation, getSettings } from '../domain/settings';
import { usersWithActiveSession } from '../database/session';
import { TELEMETRY_SERVICE_NAME, TelemetryMeterManager } from '../telemetry/TelemetryMeterManager';
import type { ManagerDefinition } from './managerModule';
import { registerManager } from './managerModule';
import { MetricFileExporter } from '../telemetry/MetricFileExporter';
import { getEntitiesListFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { BatchExportingMetricReader } from '../telemetry/BatchExportingMetricReader';

const TELEMETRY_COLLECT_INTERVAL = 5000; // 60 * 60 * 1000; // export data period in ms (correspond to 1 h)
const TELEMETRY_EXPORT_INTERVAL = 15000; // 6 * 60 * 60 * 1000; // export data period in ms (correspond to 6 h)
const SCHEDULE_TIME = 1000; // 30 * 60 * 1000; // telemetry manager period in ms (correspond to 30 min)
const TELEMETRY_MANAGER_KEY = conf.get('telemetry_manager:lock_key');
const FILIGRAN_TELEMETRY = 'https://telemetry.staging.filigran.io/v1/metrics';

const telemetryHandler = async () => {
  let resource = Resource.default();
  const filigranMetricReaders = [];
  // Fetch settings
  const context = executionContext('telemetry_manager');
  const settings = await getSettings(context) as Settings;
  const platformId = settings.id;
  // -- Resource
  const filigranResource = new Resource({
    [SEMRESATTRS_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
    [SEMRESATTRS_SERVICE_VERSION]: PLATFORM_VERSION,
    [SEMRESATTRS_SERVICE_INSTANCE_ID]: platformId,
  });
  resource = resource.merge(filigranResource);
  // File exporter
  const fileExporterReader = new BatchExportingMetricReader({
    exporter: new MetricFileExporter(AggregationTemporality.DELTA),
    collectIntervalMillis: TELEMETRY_COLLECT_INTERVAL,
    exportIntervalMillis: TELEMETRY_EXPORT_INTERVAL,
  });
  filigranMetricReaders.push(fileExporterReader);
  /* Console Exporter
  if (DEV_MODE) {
    const consoleMetric = new BatchExportingMetricReader({
      exporter: new ConsoleMetricExporter({ temporalitySelector: (instrumentType: InstrumentType) => {
        if (instrumentType === InstrumentType.OBSERVABLE_UP_DOWN_COUNTER) {
          return AggregationTemporality.CUMULATIVE;
        }
        return AggregationTemporality.DELTA;
      } }),
      collectIntervalMillis: TELEMETRY_COLLECT_INTERVAL,
      exportIntervalMillis: TELEMETRY_EXPORT_INTERVAL,
    });
    filigranMetricReaders.push(consoleMetric);
  } */
  // OTLP Exporter
  const OtlpExporterReader = new BatchExportingMetricReader({
    exporter: new OTLPMetricExporter({ url: FILIGRAN_TELEMETRY, temporalityPreference: AggregationTemporality.DELTA }),
    collectIntervalMillis: TELEMETRY_COLLECT_INTERVAL,
    exportIntervalMillis: TELEMETRY_EXPORT_INTERVAL,
  });
  filigranMetricReaders.push(OtlpExporterReader);
  // Meter Provider creation
  const filigranMeterProvider = new MeterProvider(({ resource, readers: filigranMetricReaders }));
  const filigranTelemetryMeterManager = new TelemetryMeterManager(filigranMeterProvider);
  filigranTelemetryMeterManager.registerFiligranTelemetry();
  return filigranTelemetryMeterManager;
};

const fetchTelemetryData = async (filigranTelemetryMeterManager?: TelemetryMeterManager) => {
  if (!filigranTelemetryMeterManager) {
    logApp.error('Filigran telemetry meter manager not provided', { manager: 'TELEMETRY_MANAGER' });
  } else {
    try {
      const context = executionContext('telemetry_manager');
      // Fetch settings
      const settingsArray = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_SETTINGS);
      const settings = settingsArray[0] as unknown as Settings;
      const clusterInfo = await getClusterInformation();
      // Set filigranTelemetryManager settings telemetry data
      filigranTelemetryMeterManager.setIsEEActivated(isNotEmptyField(settings.enterprise_edition) ? 1 : 0);
      filigranTelemetryMeterManager.setInstancesCount(clusterInfo.info.instances_number);
      // Get number of active users since fetchTelemetryData() last execution
      const activUsers = await usersWithActiveSession(TELEMETRY_COLLECT_INTERVAL / 1000 / 60);
      filigranTelemetryMeterManager.setActivUsersCount(activUsers.length);
    } catch (e) {
      logApp.error(e, { manager: 'TELEMETRY_MANAGER' });
    }
  }
};

const TELEMETRY_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'TELEMETRY_MANAGER',
  label: 'Telemetry manager',
  executionContext: 'telemetry_manager',
  cronSchedulerHandler: {
    handler: fetchTelemetryData,
    interval: SCHEDULE_TIME,
    lockKey: TELEMETRY_MANAGER_KEY,
    createHandlerInput: telemetryHandler,
  },
  enabledByConfig: true,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

registerManager(TELEMETRY_MANAGER_DEFINITION);

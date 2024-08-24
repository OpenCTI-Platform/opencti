import { Resource } from '@opentelemetry/resources';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { SEMRESATTRS_SERVICE_INSTANCE_ID } from '@opentelemetry/semantic-conventions/build/src/resource/SemanticResourceAttributes';
import { ConsoleMetricExporter, InstrumentType, MeterProvider } from '@opentelemetry/sdk-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { AggregationTemporality } from '@opentelemetry/sdk-metrics/build/src/export/AggregationTemporality';
import conf, { DEV_MODE, logApp, PLATFORM_VERSION } from '../config/conf';
import { executionContext, TELEMETRY_MANAGER_USER } from '../utils/access';
import { isNotEmptyField } from '../database/utils';
import type { Settings } from '../generated/graphql';
import { getClusterInformation, getSettings } from '../domain/settings';
import { usersWithActiveSessionCount } from '../database/session';
import { TELEMETRY_SERVICE_NAME, TelemetryMeterManager } from '../telemetry/TelemetryMeterManager';
import type { HandlerInput, ManagerDefinition } from './managerModule';
import { registerManager } from './managerModule';
import { MetricFileExporter } from '../telemetry/MetricFileExporter';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { BatchExportingMetricReader } from '../telemetry/BatchExportingMetricReader';
import type { BasicStoreSettings } from '../types/settings';
import { getHttpClient } from '../utils/http-client';
import type { BasicStoreEntityConnector } from '../types/connector';

const TELEMETRY_MANAGER_KEY = conf.get('telemetry_manager:lock_key');
const TELEMETRY_CONSOLE_DEBUG = conf.get('telemetry_manager:console_debug') ?? false;
const SCHEDULE_TIME = conf.get('telemetry_manager:interval') || 60000; // 1 minute default
const FILIGRAN_OTLP_TELEMETRY = DEV_MODE
  ? 'https://telemetry.staging.filigran.io/v1/metrics' : 'https://telemetry.filigran.io/v1/metrics';

const ONE_MINUTE = 60 * 1000;
const TWO_MINUTE = 2 * ONE_MINUTE;
const ONE_HOUR = 60 * ONE_MINUTE;
const SIX_HOUR = 6 * ONE_HOUR;
// Collect data period, corresponds to data point collection
const TELEMETRY_COLLECT_INTERVAL = DEV_MODE ? ONE_MINUTE : ONE_HOUR;
// Export data period, sending information to files, console and otlp
const TELEMETRY_EXPORT_INTERVAL = DEV_MODE ? TWO_MINUTE : SIX_HOUR;
// Manager schedule, data point generation
const COMPUTE_SCHEDULE_TIME = DEV_MODE ? ONE_MINUTE / 2 : ONE_HOUR / 2;

const telemetryInitializer = async (): Promise<HandlerInput> => {
  const context = executionContext('telemetry_manager');
  const filigranMetricReaders = [];
  // region File exporter
  const fileExporterReader = new BatchExportingMetricReader({
    exporter: new MetricFileExporter(AggregationTemporality.DELTA),
    collectIntervalMillis: TELEMETRY_COLLECT_INTERVAL,
    exportIntervalMillis: TELEMETRY_EXPORT_INTERVAL,
  });
  filigranMetricReaders.push(fileExporterReader);
  logApp.info('[TELEMETRY] File exporter activated');
  // endregion
  // region OTLP Exporter
  try {
    const connectivityQuery = await getHttpClient({ responseType: 'json' }).post(FILIGRAN_OTLP_TELEMETRY, {});
    if (connectivityQuery.status === 200) {
      // OtlpExporterReader can be deactivated if connectivity fail at manager start.
      const OtlpExporterReader = new BatchExportingMetricReader({
        exporter: new OTLPMetricExporter({
          url: FILIGRAN_OTLP_TELEMETRY,
          temporalityPreference: AggregationTemporality.DELTA
        }),
        collectIntervalMillis: TELEMETRY_COLLECT_INTERVAL,
        exportIntervalMillis: TELEMETRY_EXPORT_INTERVAL,
      });
      filigranMetricReaders.push(OtlpExporterReader);
      logApp.info('[TELEMETRY] Otlp exporter activated');
    } else {
      logApp.info('[TELEMETRY] Otlp exporter is deactivated for connectivity issue');
    }
  } catch {
    logApp.info('[TELEMETRY] Otlp exporter is deactivated for connectivity issue');
  }
  // endregion
  // region Console Exporter only if debug activated
  if (TELEMETRY_CONSOLE_DEBUG) {
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
    logApp.info('[TELEMETRY] Console exporter activated');
  }
  // endregion
  // Meter Provider creation
  const settings = await getSettings(context) as Settings;
  const platformId = settings.id;
  const filigranResource = new Resource({
    [SEMRESATTRS_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
    [SEMRESATTRS_SERVICE_VERSION]: PLATFORM_VERSION,
    [SEMRESATTRS_SERVICE_INSTANCE_ID]: platformId,
    'service.instance.creation': settings.created_at
  });
  const resource = Resource.default().merge(filigranResource);
  const filigranMeterProvider = new MeterProvider(({ resource, readers: filigranMetricReaders }));
  const filigranTelemetryMeterManager = new TelemetryMeterManager(filigranMeterProvider);
  filigranTelemetryMeterManager.registerFiligranTelemetry();
  return filigranTelemetryMeterManager;
};

const fetchTelemetryData = async (manager: TelemetryMeterManager) => {
  try {
    const context = executionContext('telemetry_manager');
    // region Settings information
    const settings = await getEntityFromCache<BasicStoreSettings>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_SETTINGS);
    manager.setIsEEActivated(isNotEmptyField(settings.enterprise_edition) ? 1 : 0);
    // endregion
    // region Cluster information
    const clusterInfo = await getClusterInformation();
    manager.setInstancesCount(clusterInfo.info.instances_number);
    // endregion
    // region Users information
    const activUsersCount = await usersWithActiveSessionCount(TELEMETRY_COLLECT_INTERVAL / 1000 / 60);
    manager.setActiveUsersCount(activUsersCount);
    const users = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_USER);
    manager.setUsersCount(users.length);
    // endregion
    // region Connectors information
    const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_CONNECTOR);
    const activeConnectors = connectors.filter((c) => c.active);
    manager.setActiveConnectorsCount(activeConnectors.length);
    // endregion
  } catch (e) {
    logApp.error('[TELEMETRY] Error fetching platform information', { cause: e });
  }
};

const TELEMETRY_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'TELEMETRY_MANAGER',
  label: 'Telemetry manager',
  executionContext: 'telemetry_manager',
  cronSchedulerHandler: {
    handler: fetchTelemetryData,
    handlerInitializer: telemetryInitializer, // Init meter manager is required
    infiniteInterval: COMPUTE_SCHEDULE_TIME, // Lock needs to be kept, inner scheduler will be done.
    interval: SCHEDULE_TIME,
    lockKey: TELEMETRY_MANAGER_KEY,
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

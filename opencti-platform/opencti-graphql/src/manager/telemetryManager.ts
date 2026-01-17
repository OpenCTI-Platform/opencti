import { Resource } from '@opentelemetry/resources';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { SEMRESATTRS_SERVICE_INSTANCE_ID } from '@opentelemetry/semantic-conventions/build/src/resource/SemanticResourceAttributes';
import { ConsoleMetricExporter, InstrumentType, MeterProvider } from '@opentelemetry/sdk-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { AggregationTemporality } from '@opentelemetry/sdk-metrics/build/src/export/AggregationTemporality';
import conf, { DEV_MODE, logApp, PLATFORM_VERSION } from '../config/conf';
import { executionContext, SYSTEM_USER, TELEMETRY_MANAGER_USER } from '../utils/access';
import { getClusterInformation } from '../database/cluster-module';
import { TELEMETRY_SERVICE_NAME, TelemetryMeterManager } from '../telemetry/TelemetryMeterManager';
import type { HandlerInput, ManagerDefinition } from './managerModule';
import { registerManager } from './managerModule';
import { MetricFileExporter } from '../telemetry/MetricFileExporter';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_INTERNAL_FILE, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { BatchExportingMetricReader } from '../telemetry/BatchExportingMetricReader';
import type { BasicStoreSettings } from '../types/settings';
import { getHttpClient } from '../utils/http-client';
import type { BasicStoreEntityConnector } from '../types/connector';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { elCount } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../database/utils';
import { FilterMode } from '../generated/graphql';
import { redisClearTelemetry, redisGetTelemetry, redisSetTelemetryAdd } from '../database/redis';
import type { AuthContext, AuthUser } from '../types/user';
import { ENTITY_TYPE_PIR } from '../modules/pir/pir-types';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../modules/securityCoverage/securityCoverage-types';
import { isStrategyActivated, StrategyType } from '../config/providers-configuration';
import { findRolesWithCapabilityInDraft } from '../domain/user';

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

// Region user event counters
export enum TELEMETRY_COUNT {
  GAUGE_DISSEMINATION = 'disseminationCount',
  GAUGE_NLQ = 'nlqQueryCount',
  GAUGE_REQUEST_ACCESS = 'requestAccessCreationCount',
  GAUGE_DRAFT_CREATION = 'draftCreationCount',
  GAUGE_DRAFT_VALIDATION = 'draftValidationCount',
  GAUGE_CAPABILITIES_IN_DRAFT_UPDATED = 'capabilitiesInDraftUpdateCount',
  GAUGE_WORKBENCH_UPLOAD = 'workbenchUploadCount',
  GAUGE_WORKBENCH_DRAFT_CONVERTION = 'workbenchDraftConvertionCount',
  GAUGE_WORKBENCH_VALIDATION = 'workbenchValidationCount',
  GAUGE_USER_INTO_SERVICE_ACCOUNT = 'userIntoServiceAccountCount',
  GAUGE_SERVICE_ACCOUNT_INTO_USER = 'serviceAccountIntoUserCount',
  GAUGE_USER_EMAIL_SEND = 'userEmailSendCount',
  BACKGROUND_TASK_USER = 'userBackgroundTaskCount',
  EMAIL_TEMPLATE_CREATED = 'emailTemplateCreatedCount',
  FORGOT_PASSWORD = 'forgotPasswordCount',
  CONNECTOR_DEPLOYED = 'connectorDeployedCount',
  FORM_INTAKE_CREATED = 'formIntakeCreatedCount',
  FORM_INTAKE_UPDATED = 'formIntakeUpdatedCount',
  FORM_INTAKE_DELETED = 'formIntakeDeletedCount',
  FORM_INTAKE_SUBMITTED = 'formIntakeSubmittedCount',
  USER_LOGIN = 'userLoginCount',
}

export const addTelemetryCount = async (telemetryCount: TELEMETRY_COUNT) => {
  await redisSetTelemetryAdd(telemetryCount, 1);
};
export const addUserLoginCount = () => {
  redisSetTelemetryAdd(TELEMETRY_COUNT.USER_LOGIN, 1).catch((reason) => logApp.info('Error add user login in telemetry', { reason }));
};

// End Region user event counters

const telemetryInitializer = async (): Promise<HandlerInput> => {
  const context = executionContext('telemetry_manager');
  const filigranMetricReaders = [];
  const collectorCallback = async () => {
    logApp.debug('[TELEMETRY] Clearing all telemetry data in Redis');
    await redisClearTelemetry();
  };
  // region File exporter
  const fileExporterReader = new BatchExportingMetricReader({
    exporter: new MetricFileExporter(AggregationTemporality.DELTA),
    collectIntervalMillis: TELEMETRY_COLLECT_INTERVAL,
    exportIntervalMillis: TELEMETRY_EXPORT_INTERVAL,
    collectCallback: collectorCallback,
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
          temporalityPreference: AggregationTemporality.DELTA,
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
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const platformId = settings.id;
  const filigranResource = new Resource({
    [SEMRESATTRS_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
    [SEMRESATTRS_SERVICE_VERSION]: PLATFORM_VERSION,
    [SEMRESATTRS_SERVICE_INSTANCE_ID]: platformId,
    'service.instance.creation': settings.created_at as unknown as string,
  });
  const resource = Resource.default().merge(filigranResource);
  const filigranMeterProvider = new MeterProvider(({ resource, readers: filigranMetricReaders }));
  const filigranTelemetryMeterManager = new TelemetryMeterManager(filigranMeterProvider);
  filigranTelemetryMeterManager.registerFiligranTelemetry();
  return filigranTelemetryMeterManager;
};

// Settings information
const fetchSettingsData = async (context: AuthContext, manager: TelemetryMeterManager) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_SETTINGS);
  manager.setIsEEActivated(settings.valid_enterprise_edition === true ? 1 : 0);
};
// Cluster information
const fetchClusterData = async (manager: TelemetryMeterManager) => {
  const clusterInfo = await getClusterInformation();
  manager.setInstancesCount(clusterInfo.info.instances_number);
};
// Users information
const fetchUsersData = async (context: AuthContext, manager: TelemetryMeterManager) => {
  const users = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_USER) as AuthUser[];
  manager.setUsersCount(users.filter((user) => !user.user_service_account).length);
  manager.setServiceAccountsCount(users.filter((user) => user.user_service_account === true).length);
};
// Roles with draft capability information
const fetchRolesWithCapabilityInDraftData = async (context: AuthContext, manager: TelemetryMeterManager) => {
  const rolesWithCapabilityInDraft = await findRolesWithCapabilityInDraft(context, TELEMETRY_MANAGER_USER);
  manager.setRolesWithCapabilityInDraftCount(rolesWithCapabilityInDraft.length);
};
// Connectors information
const fetchConnectorsData = async (context: AuthContext, manager: TelemetryMeterManager) => {
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_CONNECTOR);
  const activeConnectors = connectors.filter((c) => c.active);
  manager.setActiveConnectorsCount(activeConnectors.length);
};
// Draft information
const fetchDraftsData = async (context: AuthContext, manager: TelemetryMeterManager) => {
  const draftWorkspaces = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
  manager.setDraftCount(draftWorkspaces.length);
};
// Workbenches information
const fetchWorkbenchesData = async (context: AuthContext, manager: TelemetryMeterManager) => {
  const pendingFileFilter = {
    mode: FilterMode.And,
    filters: [{ key: ['internal_id'], values: ['import/pending'], operator: 'starts_with' }],
    filterGroups: [],
  };
  const workbenchesCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { filters: pendingFileFilter, types: [ENTITY_TYPE_INTERNAL_FILE] });
  manager.setWorkbenchCount(workbenchesCount);
};
// PIR information
const fetchPirsData = async (context: AuthContext, manager: TelemetryMeterManager) => {
  const pirs = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_PIR);
  manager.setPirCount(pirs.length);
};
// SSO providers configuration
const fetchSsoProvidersData = async (manager: TelemetryMeterManager) => {
  manager.setSsoLocalStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_LOCAL) ? 1 : 0);
  manager.setSsoOpenidStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_OPENID) ? 1 : 0);
  manager.setSsoLDAPStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_LDAP) ? 1 : 0);
  manager.setSsoSAMLStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_SAML) ? 1 : 0);
  manager.setSsoAuthZeroStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_AUTH0) ? 1 : 0);
  manager.setSsoCertStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_CERT) ? 1 : 0);
  manager.setSsoHeaderStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_HEADER) ? 1 : 0);
  manager.setSsoFacebookStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_FACEBOOK) ? 1 : 0);
  manager.setSsoGoogleStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_GOOGLE) ? 1 : 0);
  manager.setSsoGithubStrategyEnabled(isStrategyActivated(StrategyType.STRATEGY_GITHUB) ? 1 : 0);
};
// Security Coverages
const fetchSecurityCoveragesData = async (context: AuthContext, manager: TelemetryMeterManager) => {
  const securityCoveragesCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, {
    types: [ENTITY_TYPE_SECURITY_COVERAGE],
  });
  manager.setSecurityCoveragesCount(securityCoveragesCount);
};
// Telemetry user events
const fetchTelemetryCountsData = async (manager: TelemetryMeterManager) => {
  const telemetryCounts = [
    { count: TELEMETRY_COUNT.GAUGE_DISSEMINATION, setter: manager.setDisseminationCount },
    { count: TELEMETRY_COUNT.GAUGE_NLQ, setter: manager.setNlqQueryCount },
    { count: TELEMETRY_COUNT.GAUGE_REQUEST_ACCESS, setter: manager.setRequestAccessCreatedCount },
    { count: TELEMETRY_COUNT.GAUGE_DRAFT_CREATION, setter: manager.setDraftCreationCount },
    { count: TELEMETRY_COUNT.GAUGE_DRAFT_VALIDATION, setter: manager.setDraftValidationCount },
    { count: TELEMETRY_COUNT.GAUGE_CAPABILITIES_IN_DRAFT_UPDATED, setter: manager.setCapabilitiesInDraftUpdatedCount },
    { count: TELEMETRY_COUNT.GAUGE_WORKBENCH_UPLOAD, setter: manager.setWorkbenchUploadCount },
    { count: TELEMETRY_COUNT.GAUGE_WORKBENCH_DRAFT_CONVERTION, setter: manager.setWorkbenchDraftConvertionCount },
    { count: TELEMETRY_COUNT.GAUGE_WORKBENCH_VALIDATION, setter: manager.setWorkbenchValidationCount },
    { count: TELEMETRY_COUNT.GAUGE_USER_INTO_SERVICE_ACCOUNT, setter: manager.setUserIntoServiceAccountCount },
    { count: TELEMETRY_COUNT.GAUGE_SERVICE_ACCOUNT_INTO_USER, setter: manager.setServiceAccountIntoUserCount },
    { count: TELEMETRY_COUNT.GAUGE_USER_EMAIL_SEND, setter: manager.setUserEmailSendCount },
    { count: TELEMETRY_COUNT.BACKGROUND_TASK_USER, setter: manager.setUserBackgroundTaskCount },
    { count: TELEMETRY_COUNT.EMAIL_TEMPLATE_CREATED, setter: manager.setEmailTemplateCreatedCount },
    { count: TELEMETRY_COUNT.FORGOT_PASSWORD, setter: manager.setForgotPasswordCount },
    { count: TELEMETRY_COUNT.CONNECTOR_DEPLOYED, setter: manager.setConnectorDeployedCount },
    { count: TELEMETRY_COUNT.USER_LOGIN, setter: manager.setUserLoginCount },
    { count: TELEMETRY_COUNT.FORM_INTAKE_CREATED, setter: manager.setFormIntakeCreatedCount },
    { count: TELEMETRY_COUNT.FORM_INTAKE_UPDATED, setter: manager.setFormIntakeUpdatedCount },
    { count: TELEMETRY_COUNT.FORM_INTAKE_DELETED, setter: manager.setFormIntakeDeletedCount },
    { count: TELEMETRY_COUNT.FORM_INTAKE_SUBMITTED, setter: manager.setFormIntakeSubmittedCount },
  ];

  await Promise.all(telemetryCounts.map(async ({ count, setter }) => {
    const countInRedis = await redisGetTelemetry(count);
    setter(countInRedis);
  }));
};

export const fetchTelemetryData = async (manager: TelemetryMeterManager) => {
  try {
    const context = executionContext('telemetry_manager');
    await fetchSettingsData(context, manager);
    await fetchClusterData(manager);
    await fetchUsersData(context, manager);
    await fetchConnectorsData(context, manager);
    await fetchRolesWithCapabilityInDraftData(context, manager);
    await fetchDraftsData(context, manager);
    await fetchWorkbenchesData(context, manager);
    await fetchPirsData(context, manager);
    await fetchSsoProvidersData(manager);
    await fetchSecurityCoveragesData(context, manager);
    await fetchTelemetryCountsData(manager);
    logApp.debug('[TELEMETRY] Fetching telemetry data successfully');
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
  },
};

registerManager(TELEMETRY_MANAGER_DEFINITION);

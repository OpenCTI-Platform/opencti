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
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { FilterMode } from '../generated/graphql';
import { redisClearTelemetry, redisGetTelemetry, redisSetTelemetryAdd } from '../database/redis';
import type { AuthUser } from '../types/user';
import { ENTITY_TYPE_PIR } from '../modules/pir/pir-types';

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
export const TELEMETRY_GAUGE_DISSEMINATION = 'disseminationCount';
export const TELEMETRY_GAUGE_NLQ = 'nlqQueryCount';
export const TELEMETRY_GAUGE_REQUEST_ACCESS = 'requestAccessCreationCount';
export const TELEMETRY_GAUGE_DRAFT_CREATION = 'draftCreationCount';
export const TELEMETRY_GAUGE_DRAFT_VALIDATION = 'draftValidationCount';
export const TELEMETRY_GAUGE_WORKBENCH_UPLOAD = 'workbenchUploadCount';
export const TELEMETRY_GAUGE_WORKBENCH_DRAFT_CONVERTION = 'workbenchDraftConvertionCount';
export const TELEMETRY_GAUGE_WORKBENCH_VALIDATION = 'workbenchValidationCount';
export const TELEMETRY_GAUGE_USER_INTO_SERVICE_ACCOUNT = 'userIntoServiceAccountCount';
export const TELEMETRY_GAUGE_SERVICE_ACCOUNT_INTO_USER = 'serviceAccountIntoUserCount';
export const TELEMETRY_GAUGE_USER_EMAIL_SEND = 'userEmailSendCount';
export const TELEMETRY_GAUGE_ONBOARDING_EMAIL_SEND = 'onboardingEmailSendCount';
export const TELEMETRY_BACKGROUND_TASK_USER = 'userBackgroundTaskCount';
export const TELEMETRY_EMAIL_TEMPLATE_CREATED = 'emailTemplateCreatedCount';
export const TELEMETRY_FORGOT_PASSWORD = 'forgotPasswordCount';
export const TELEMETRY_CONNECTOR_DEPLOYED = 'connectorDeployedCount';
export const TELEMETRY_FORM_INTAKE_CREATED = 'formIntakeCreatedCount';
export const TELEMETRY_FORM_INTAKE_UPDATED = 'formIntakeUpdatedCount';
export const TELEMETRY_FORM_INTAKE_DELETED = 'formIntakeDeletedCount';
export const TELEMETRY_FORM_INTAKE_SUBMITTED = 'formIntakeSubmittedCount';
export const TELEMETRY_USER_LOGIN = 'userLoginCount';

export const addDisseminationCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_DISSEMINATION, 1);
};
export const addNlqQueryCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_NLQ, 1);
};
export const addRequestAccessCreationCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_REQUEST_ACCESS, 1);
};
export const addDraftCreationCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_DRAFT_CREATION, 1);
};
export const addDraftValidationCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_DRAFT_VALIDATION, 1);
};
export const addWorkbenchUploadCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_WORKBENCH_UPLOAD, 1);
};
export const addWorkbenchDraftConvertionCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_WORKBENCH_DRAFT_CONVERTION, 1);
};
export const addWorkbenchValidationCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_WORKBENCH_VALIDATION, 1);
};
export const addUserIntoServiceAccountCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_USER_INTO_SERVICE_ACCOUNT, 1);
};

export const addServiceAccountIntoUserCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_SERVICE_ACCOUNT_INTO_USER, 1);
};

export const addUserEmailSendCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_USER_EMAIL_SEND, 1);
};

export const addOnboardingEmailSendCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_ONBOARDING_EMAIL_SEND, 1);
};

export const addFormIntakeCreatedCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_FORM_INTAKE_CREATED, 1);
};

export const addFormIntakeUpdatedCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_FORM_INTAKE_UPDATED, 1);
};

export const addFormIntakeDeletedCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_FORM_INTAKE_DELETED, 1);
};

export const addFormIntakeSubmittedCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_FORM_INTAKE_SUBMITTED, 1);
};

export const addUserBackgroundTaskCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_BACKGROUND_TASK_USER, 1);
};

export const addEmailTemplateCreatedCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_EMAIL_TEMPLATE_CREATED, 1);
};

export const addForgotPasswordCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_FORGOT_PASSWORD, 1);
};

export const addConnectorDeployedCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_CONNECTOR_DEPLOYED, 1);
};

export const addUserLoginCount = () => {
  redisSetTelemetryAdd(TELEMETRY_USER_LOGIN, 1).catch((reason) => logApp.info('Error add user login in telemetry', { reason }));
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
    collectCallback: collectorCallback
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
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const platformId = settings.id;
  const filigranResource = new Resource({
    [SEMRESATTRS_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
    [SEMRESATTRS_SERVICE_VERSION]: PLATFORM_VERSION,
    [SEMRESATTRS_SERVICE_INSTANCE_ID]: platformId,
    'service.instance.creation': settings.created_at as unknown as string
  });
  const resource = Resource.default().merge(filigranResource);
  const filigranMeterProvider = new MeterProvider(({ resource, readers: filigranMetricReaders }));
  const filigranTelemetryMeterManager = new TelemetryMeterManager(filigranMeterProvider);
  filigranTelemetryMeterManager.registerFiligranTelemetry();
  return filigranTelemetryMeterManager;
};

export const fetchTelemetryData = async (manager: TelemetryMeterManager) => {
  try {
    const context = executionContext('telemetry_manager');

    // region Settings information
    const settings = await getEntityFromCache<BasicStoreSettings>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_SETTINGS);
    manager.setIsEEActivated(settings.valid_enterprise_edition === true ? 1 : 0);
    // endregion

    // region Cluster information
    const clusterInfo = await getClusterInformation();
    manager.setInstancesCount(clusterInfo.info.instances_number);
    // endregion

    // region Users information
    const users = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_USER) as AuthUser[];
    manager.setUsersCount(users.filter((user) => !user.user_service_account).length);
    manager.setServiceAccountsCount(users.filter((user) => user.user_service_account === true).length);
    // endregion

    // region Connectors information
    const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_CONNECTOR);
    const activeConnectors = connectors.filter((c) => c.active);
    manager.setActiveConnectorsCount(activeConnectors.length);
    // endregion

    // region Draft information
    const draftWorkspaces = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
    manager.setDraftCount(draftWorkspaces.length);
    // endregion

    // region Workbenches information
    const pendingFileFilter = {
      mode: FilterMode.And,
      filters: [{ key: ['internal_id'], values: ['import/pending'], operator: 'starts_with' }],
      filterGroups: []
    };
    const workbenchesCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { filters: pendingFileFilter, types: [ENTITY_TYPE_INTERNAL_FILE] });
    manager.setWorkbenchCount(workbenchesCount);
    // endregion

    // region PIR information
    const pirs = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_PIR);
    manager.setPirCount(pirs.length);
    // endregion

    // region Telemetry user events
    const disseminationCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_DISSEMINATION);
    manager.setDisseminationCount(disseminationCountInRedis);
    const nlqQueryCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_NLQ);
    manager.setNlqQueryCount(nlqQueryCountInRedis);
    const requestAccessCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_REQUEST_ACCESS);
    manager.setRequestAccessCreatedCount(requestAccessCountInRedis);
    const draftCreationCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_DRAFT_CREATION);
    manager.setDraftCreationCount(draftCreationCountInRedis);
    const draftValidationCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_DRAFT_VALIDATION);
    manager.setDraftValidationCount(draftValidationCountInRedis);
    const workbenchUploadCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_WORKBENCH_UPLOAD);
    manager.setWorkbenchUploadCount(workbenchUploadCountInRedis);
    const workbenchDraftConvertionCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_WORKBENCH_DRAFT_CONVERTION);
    manager.setWorkbenchDraftConvertionCount(workbenchDraftConvertionCountInRedis);
    const workbenchValidationCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_WORKBENCH_VALIDATION);
    manager.setWorkbenchValidationCount(workbenchValidationCountInRedis);
    const userIntoServiceAccountCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_USER_INTO_SERVICE_ACCOUNT);
    manager.setUserIntoServiceAccountCount(userIntoServiceAccountCountInRedis);
    const serviceAccountIntoUserCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_SERVICE_ACCOUNT_INTO_USER);
    manager.setServiceAccountIntoUserCount(serviceAccountIntoUserCountInRedis);
    const emailSendCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_USER_EMAIL_SEND);
    manager.setUserEmailSendCount(emailSendCountInRedis);
    const onboardingEmailSendCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_ONBOARDING_EMAIL_SEND);
    manager.setOnboardingEmailSendCount(onboardingEmailSendCountInRedis);
    const userBackgroundTaskCountInRedis = await redisGetTelemetry(TELEMETRY_BACKGROUND_TASK_USER);
    manager.setUserBackgroundTaskCount(userBackgroundTaskCountInRedis);
    const emailTemplateCreatedCountInRedis = await redisGetTelemetry(TELEMETRY_EMAIL_TEMPLATE_CREATED);
    manager.setEmailTemplateCreatedCount(emailTemplateCreatedCountInRedis);
    const forgotPasswordCountInRedis = await redisGetTelemetry(TELEMETRY_FORGOT_PASSWORD);
    manager.setForgotPasswordCount(forgotPasswordCountInRedis);
    const connectorDeployedCountInRedis = await redisGetTelemetry(TELEMETRY_CONNECTOR_DEPLOYED);
    manager.setConnectorDeployedCount(connectorDeployedCountInRedis);
    const userLoginCountInRedis = await redisGetTelemetry(TELEMETRY_USER_LOGIN);
    manager.setUserLoginCount(userLoginCountInRedis);
    const formIntakeCreatedCountInRedis = await redisGetTelemetry(TELEMETRY_FORM_INTAKE_CREATED);
    manager.setFormIntakeCreatedCount(formIntakeCreatedCountInRedis);
    const formIntakeUpdatedCountInRedis = await redisGetTelemetry(TELEMETRY_FORM_INTAKE_UPDATED);
    manager.setFormIntakeUpdatedCount(formIntakeUpdatedCountInRedis);
    const formIntakeDeletedCountInRedis = await redisGetTelemetry(TELEMETRY_FORM_INTAKE_DELETED);
    manager.setFormIntakeDeletedCount(formIntakeDeletedCountInRedis);
    const formIntakeSubmittedCountInRedis = await redisGetTelemetry(TELEMETRY_FORM_INTAKE_SUBMITTED);
    manager.setFormIntakeSubmittedCount(formIntakeSubmittedCountInRedis);
    // end region Telemetry user events

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
  }
};

registerManager(TELEMETRY_MANAGER_DEFINITION);

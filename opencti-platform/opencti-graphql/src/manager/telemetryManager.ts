import { defaultResource, resourceFromAttributes } from '@opentelemetry/resources';
import { ATTR_SERVICE_INSTANCE_ID, ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { AggregationTemporality, ConsoleMetricExporter, InstrumentType, MeterProvider, type IMetricReader } from '@opentelemetry/sdk-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import conf, { DEV_MODE, logApp, PLATFORM_VERSION } from '../config/conf';
import { executionContext, SYSTEM_USER, TELEMETRY_MANAGER_USER } from '../utils/access';
import { getClusterInformation } from '../database/cluster-module';
import {
  computeActiveConnectorsByIdentity,
  type DimensionalGaugeItem,
  normalizeTelemetryTags,
  TELEMETRY_SERVICE_NAME,
  TelemetryMeterManager,
} from '../telemetry/TelemetryMeterManager';
import type { HandlerInput, ManagerDefinition } from './managerModule';
import { registerManager } from './managerModule';
import { MetricFileExporter } from '../telemetry/MetricFileExporter';
import { getEntitiesListFromCache, getEntityFromCache } from '../database/cache';
import {
  ENTITY_TYPE_CONNECTOR,
  ENTITY_TYPE_FEED,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_INTERNAL_FILE,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_RULE,
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_SYNC,
  ENTITY_TYPE_TAXII_COLLECTION,
  ENTITY_TYPE_USER,
} from '../schema/internalObject';
import { BatchExportingMetricReader } from '../telemetry/BatchExportingMetricReader';
import type { BasicStoreSettings } from '../types/settings';
import { getHttpClient } from '../utils/http-client';
import type { BasicStoreEntityConnector } from '../types/connector';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../modules/draftWorkspace/draftWorkspace-types';
import { type BasicStoreEntitySavedFilter, ENTITY_TYPE_SAVED_FILTER } from '../modules/savedFilter/savedFilter-types';
import { elAggregationCount, elCount } from '../database/engine';
import {
  READ_INDEX_FILES,
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
} from '../database/utils';
import type { BasicStoreEntity } from '../types/store';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { NOTIFIER_CONNECTOR_EMAIL, NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL, NOTIFIER_CONNECTOR_UI, NOTIFIER_CONNECTOR_WEBHOOK } from '../modules/notifier/notifier-statics';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { ENTITY_TYPE_PUBLIC_DASHBOARD } from '../modules/publicDashboard/publicDashboard-types';
import { ENTITY_TYPE_STREAM_COLLECTION } from '../modules/dataSharing/streamCollection-types';
import {
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
} from '../modules/ingestion/ingestion-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../modules/managerConfiguration/managerConfiguration-types';
import { getSupportedContractsByImage } from '../modules/catalog/catalog-domain';
import { FilterMode } from '../generated/graphql';
import { redisClearTelemetry, redisGetTelemetry, redisSetTelemetryAdd } from '../database/redis';
import type { AuthUser } from '../types/user';
import { ENTITY_TYPE_PIR } from '../modules/pir/pir-types';
import { ENTITY_TYPE_SECURITY_COVERAGE } from '../modules/securityCoverage/securityCoverage-types';
import { findRolesWithCapabilityInDraft } from '../domain/user';
import { isEnterpriseEditionFromSettings } from '../enterprise-edition/ee';
import { EnvStrategyType, isStrategyActivated } from '../modules/authenticationProvider/providers-configuration';
import { listRules } from '../modules/retentionRules/retentionRules-domain';
import { fullEntitiesList } from '../database/middleware-loader';
import { isSavedFilterShared } from '../modules/savedFilter/savedFilter-domain';

const TELEMETRY_MANAGER_KEY = conf.get('telemetry_manager:lock_key');

// Curated allowlist of knowledge object types exported by the
// knowledge_objects_by_type gauge (attribute values are the lowercased
// entity types). Kept bounded on purpose - this is a product adoption
// signal, not a full data model census.
const KNOWLEDGE_OBJECT_TYPES = [
  'Report',
  'Grouping',
  'Note',
  'Opinion',
  'Case-Incident',
  'Case-Rfi',
  'Case-Rft',
  'Task',
  'Feedback',
  'Indicator',
  'Malware',
  'Intrusion-Set',
  'Threat-Actor-Group',
  'Threat-Actor-Individual',
  'Incident',
];

// Structural subset used by the cache-based snapshot collectors below - kept
// minimal so the collectors do not depend on each module's full store type.
type DataShareLike = BasicStoreEntity & { stream_public?: boolean; enabled?: boolean };

// Filter matching entities whose boolean attribute is true (ES count queries).
const booleanTrueFilter = (key: string) => ({
  mode: FilterMode.And,
  filters: [{ key: [key], values: ['true'] }],
  filterGroups: [],
});
const TELEMETRY_CONSOLE_DEBUG = conf.get('telemetry_manager:console_debug') ?? false;
const SCHEDULE_TIME = conf.get('telemetry_manager:interval') || 60000; // 1 minute default
const FILIGRAN_OTLP_TELEMETRY = DEV_MODE
  ? 'https://telemetry.staging.filigran.io/v1/metrics'
  : 'https://telemetry.filigran.io/v1/metrics';

const ONE_MINUTE = 60 * 1000;
const ONE_HOUR = 60 * ONE_MINUTE;
const THREE_HOUR = 3 * ONE_HOUR;
const SIX_HOUR = 6 * ONE_HOUR;
// Collect data period, corresponds to data point collection
const TELEMETRY_COLLECT_INTERVAL = DEV_MODE ? ONE_MINUTE : ONE_HOUR;
// Export data period, sending information to files, console and otlp.
// Dev mode uses a 3h window instead of the production 6h: tight-enough to
// observe a full cycle in a working day, without flooding the staging
// collector (one object per export per instance) when many dev instances
// run at once.
const TELEMETRY_EXPORT_INTERVAL = DEV_MODE ? THREE_HOUR : SIX_HOUR;
// Manager schedule, data point generation
const COMPUTE_SCHEDULE_TIME = DEV_MODE ? ONE_MINUTE / 2 : ONE_HOUR / 2;

// Region user event counters
export const TELEMETRY_GAUGE_DISSEMINATION = 'disseminationCount';
export const TELEMETRY_GAUGE_NLQ = 'nlqQueryCount';
export const TELEMETRY_GAUGE_REQUEST_ACCESS = 'requestAccessCreationCount';
export const TELEMETRY_GAUGE_DRAFT_CREATION = 'draftCreationCount';
export const TELEMETRY_GAUGE_DRAFT_VALIDATION = 'draftValidationCount';
export const TELEMETRY_GAUGE_CAPABILITIES_IN_DRAFT_UPDATED = 'capabilitiesInDraftUpdateCount';
export const TELEMETRY_GAUGE_WORKBENCH_UPLOAD = 'workbenchUploadCount';
export const TELEMETRY_GAUGE_WORKBENCH_DRAFT_CONVERTION = 'workbenchDraftConvertionCount';
export const TELEMETRY_GAUGE_WORKBENCH_VALIDATION = 'workbenchValidationCount';
export const TELEMETRY_GAUGE_USER_INTO_SERVICE_ACCOUNT = 'userIntoServiceAccountCount';
export const TELEMETRY_GAUGE_SERVICE_ACCOUNT_INTO_USER = 'serviceAccountIntoUserCount';
export const TELEMETRY_GAUGE_USER_EMAIL_SEND = 'userEmailSendCount';
export const TELEMETRY_BACKGROUND_TASK_USER = 'userBackgroundTaskCount';
export const TELEMETRY_EMAIL_TEMPLATE_CREATED = 'emailTemplateCreatedCount';
export const TELEMETRY_FORGOT_PASSWORD = 'forgotPasswordCount';
export const TELEMETRY_CONNECTOR_DEPLOYED = 'connectorDeployedCount';
export const TELEMETRY_FORM_INTAKE_CREATED = 'formIntakeCreatedCount';
export const TELEMETRY_FORM_INTAKE_UPDATED = 'formIntakeUpdatedCount';
export const TELEMETRY_FORM_INTAKE_DELETED = 'formIntakeDeletedCount';
export const TELEMETRY_FORM_INTAKE_SUBMITTED = 'formIntakeSubmittedCount';
export const TELEMETRY_USER_LOGIN = 'userLoginCount';
export const TELEMETRY_GAUGE_DECAY_RULE_CREATION = 'decayRuleCreationCount';
export const TELEMETRY_GAUGE_CUSTOM_VIEW_CREATED = 'customViewCreatedCount';
export const TELEMETRY_GAUGE_CUSTOM_VIEW_ENABLED = 'customViewEnabledCount';
export const TELEMETRY_GAUGE_SAVED_FILTER_PERMISSION_CHANGES = 'sharedSavedFiltersPermissionChangesCount';
export const TELEMETRY_GAUGE_WORKFLOW_PUBLISH = 'workflowPublishCount';
// AI usage counters. Backend-agnostic by design: a chatbot message or an Ask AI
// call is the SAME feature whether it is served by the legacy path or by
// XTM One, so no counter carries a legacy/xtm_one dimension. The before/after
// XTM One adoption analysis is done in analytics by segmenting instances on
// the is_xtm_one_configured gauge.
export const TELEMETRY_GAUGE_CHATBOT_MESSAGE = 'chatbotMessageCount';
export const TELEMETRY_GAUGE_AI_INSIGHT_REQUEST = 'aiInsightRequestCount';
export const TELEMETRY_GAUGE_ASK_AI_QUERY = 'askAiQueryCount';
export const TELEMETRY_GAUGE_XTM_AGENT_CALL = 'xtmAgentCallCount';
export const TELEMETRY_GAUGE_PLAYBOOK_AI_AGENT_RUN = 'playbookAiAgentRunCount';
// Product usage counters
export const TELEMETRY_GAUGE_PLAYBOOK_EXECUTION = 'playbookExecutionCount';
export const TELEMETRY_GAUGE_NOTIFICATION_SENT = 'notificationSentCount';
export const TELEMETRY_GAUGE_EXPORT_GENERATED = 'exportGeneratedCount';
export const TELEMETRY_GAUGE_INGESTION_OBJECTS_PROCESSED = 'ingestionObjectsProcessedCount';

// Bounded enums for dimensional counters (cardinality discipline: every
// dimension value set is a closed list, mirrored by the warehouse models).
export const ASK_AI_FEATURES = [
  'fix_spelling',
  'make_shorter',
  'make_longer',
  'change_tone',
  'summarize',
  'explain',
  'container_report',
  'summarize_files',
  'convert_files_to_stix',
  'activity',
  'forecast',
  'history',
  'container_summary',
] as const;
export type AskAiFeature = typeof ASK_AI_FEATURES[number];
export const AI_INSIGHT_CACHE_STATES = ['hit', 'miss'] as const;
export type AiInsightCacheState = typeof AI_INSIGHT_CACHE_STATES[number];
export const XTM_AGENT_CHANNELS = ['direct', 'direct_files'] as const;
export type XtmAgentChannel = typeof XTM_AGENT_CHANNELS[number];
export const NOTIFICATION_CHANNELS = ['email', 'webhook', 'ui'] as const;
export type NotificationChannel = typeof NOTIFICATION_CHANNELS[number];
// Providers supported by the built-in LLM configuration (see database/ai-llm.ts).
// Any other configured value is exported as 'other' to keep the is_ai_enabled
// type dimension bounded.
export const AI_PROVIDER_TYPES = ['mistralai', 'openai', 'azureopenai'] as const;

export const addDisseminationCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_DISSEMINATION, 1);
};
// Fire-and-forget (like the other feature counters below): a telemetry
// failure must never break the NLQ feature.
export const addNlqQueryCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_NLQ, 1)
    .catch((reason) => logApp.warn('Error adding NLQ query count to telemetry', { reason }));
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
export const addCapabilitiesInDraftUpdatedCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_CAPABILITIES_IN_DRAFT_UPDATED, 1);
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

export const addDecayRuleCreationCount = async () => {
  await redisSetTelemetryAdd(TELEMETRY_GAUGE_DECAY_RULE_CREATION, 1);
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

export const addCustomViewCreatedCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_CUSTOM_VIEW_CREATED, 1)
    .catch((reason) => logApp.warn('Error adding custom view created count to telemetry', { reason }));
};

export const addCustomViewEnabledCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_CUSTOM_VIEW_ENABLED, 1)
    .catch((reason) => logApp.warn('Error adding custom view enabled count to telemetry', { reason }));
};

export const addSharedSavedFiltersPermissionChangesCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_SAVED_FILTER_PERMISSION_CHANGES, 1)
    .catch((reason) => logApp.warn('Error adding shared saved filters permission changes count to telemetry', { reason }));
};

export const addWorkflowPublishCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_WORKFLOW_PUBLISH, 1)
    .catch((reason) => logApp.warn('Error adding workflow publish count to telemetry', { reason }));
};

// All the counters below are fire-and-forget: they are called from feature
// hot paths (HTTP handlers, domain functions), so a Redis failure must never
// break the feature itself - it is only logged.
// One chatbot message sent, whatever the serving backend (legacy Flowise or XTM One).
export const addChatbotMessageCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_CHATBOT_MESSAGE, 1)
    .catch((reason) => logApp.warn('Error adding chatbot message count to telemetry', { reason }));
};

export const addAiInsightRequestCount = (cache: AiInsightCacheState) => {
  redisSetTelemetryAdd(`${TELEMETRY_GAUGE_AI_INSIGHT_REQUEST}:${cache}`, 1)
    .catch((reason) => logApp.warn('Error adding AI insight request count to telemetry', { reason }));
};

// Counted at the feature entry point (domain function), not in the LLM client,
// so the number does not move if a feature is re-routed to another backend.
export const addAskAiQueryCount = (feature: AskAiFeature) => {
  redisSetTelemetryAdd(`${TELEMETRY_GAUGE_ASK_AI_QUERY}:${feature}`, 1)
    .catch((reason) => logApp.warn('Error adding Ask AI query count to telemetry', { reason }));
};

export const addXtmAgentCallCount = (channel: XtmAgentChannel) => {
  redisSetTelemetryAdd(`${TELEMETRY_GAUGE_XTM_AGENT_CALL}:${channel}`, 1)
    .catch((reason) => logApp.warn('Error adding XTM agent call count to telemetry', { reason }));
};

// Fire-and-forget: a telemetry failure must never break a playbook run.
export const addPlaybookAiAgentRunCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_PLAYBOOK_AI_AGENT_RUN, 1)
    .catch((reason) => logApp.warn('Error adding playbook AI agent run count to telemetry', { reason }));
};

export const addPlaybookExecutionCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_PLAYBOOK_EXECUTION, 1)
    .catch((reason) => logApp.warn('Error adding playbook execution count to telemetry', { reason }));
};

export const addNotificationSentCount = (channel: NotificationChannel) => {
  redisSetTelemetryAdd(`${TELEMETRY_GAUGE_NOTIFICATION_SENT}:${channel}`, 1)
    .catch((reason) => logApp.warn('Error adding notification sent count to telemetry', { reason }));
};

export const addExportGeneratedCount = () => {
  redisSetTelemetryAdd(TELEMETRY_GAUGE_EXPORT_GENERATED, 1)
    .catch((reason) => logApp.warn('Error adding export generated count to telemetry', { reason }));
};

// Volume counter: adds the number of objects processed by a completed work.
export const addIngestionObjectsProcessedCount = (count: number) => {
  // Floored because the Redis accumulation relies on the integer-only HINCRBY.
  const objectsCount = Math.floor(count);
  if (!Number.isFinite(objectsCount) || objectsCount <= 0) {
    return;
  }
  redisSetTelemetryAdd(TELEMETRY_GAUGE_INGESTION_OBJECTS_PROCESSED, objectsCount)
    .catch((reason) => logApp.warn('Error adding ingestion objects processed count to telemetry', { reason }));
};

// End Region user event counters

const telemetryInitializer = async (): Promise<HandlerInput> => {
  const startTime = Date.now();
  const context = executionContext('telemetry_manager');
  const filigranMetricReaders: IMetricReader[] = [];
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
  const filigranResourceAttributes: Record<string, string> = {
    [ATTR_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
    [ATTR_SERVICE_VERSION]: PLATFORM_VERSION,
    [ATTR_SERVICE_INSTANCE_ID]: platformId,
    'service.instance.creation': settings.created_at as unknown as string,
  };
  // Optional deployment tags (telemetry_manager:tags / TELEMETRY_MANAGER__TAGS,
  // normalized to a canonical sorted/lowercased comma string). One resource
  // attribute on every export so analytics can slice any metric by deployment
  // dimension (e.g. "saas,eu-west"). Omitted entirely when not configured.
  const telemetryTags = normalizeTelemetryTags(conf.get('telemetry_manager:tags'));
  if (telemetryTags.length > 0) {
    filigranResourceAttributes['filigran.telemetry.tags'] = telemetryTags;
  }
  const filigranResource = resourceFromAttributes(filigranResourceAttributes);
  const resource = defaultResource().merge(filigranResource);
  const filigranMeterProvider = new MeterProvider(({ resource, readers: filigranMetricReaders }));
  const filigranTelemetryMeterManager = new TelemetryMeterManager(filigranMeterProvider);
  filigranTelemetryMeterManager.registerFiligranTelemetry();
  logApp.info(`[TELEMETRY] Initialized in ${new Date().getTime() - startTime} ms`);
  return filigranTelemetryMeterManager;
};

export const fetchTelemetryData = async (manager: TelemetryMeterManager) => {
  const startTime = Date.now();
  try {
    const context = executionContext('telemetry_manager');
    // region Settings information
    const settings = await getEntityFromCache<BasicStoreSettings>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_SETTINGS);
    manager.setIsEEActivated(isEnterpriseEditionFromSettings(settings) ? 1 : 0);
    // endregion

    // region AI / ecosystem configuration gauges
    // These booleans are the segmentation keys used by analytics to compare
    // AI feature adoption before/after an XTM One deployment - usage counters
    // themselves never carry a legacy/xtm_one dimension.
    const aiEnabled = conf.get('ai:enabled') === true || conf.get('ai:enabled') === 'true';
    const configuredAiType: string = conf.get('ai:type') ?? '';
    // Bounded enum: none when disabled, a known provider, or 'other' for any
    // unrecognized configured value (misconfiguration must not explode the
    // dimension cardinality).
    let aiType = 'none';
    if (aiEnabled) {
      aiType = (AI_PROVIDER_TYPES as readonly string[]).includes(configuredAiType) ? configuredAiType : 'other';
    }
    manager.setIsAiEnabledItems([{ value: aiEnabled ? 1 : 0, attributes: { type: aiType } }]);
    const isXtmOneConfigured = !!(conf.get('xtm:xtm_one_url') && conf.get('xtm:xtm_one_token'));
    manager.setIsXtmOneConfigured(isXtmOneConfigured ? 1 : 0);
    manager.setIsChatbotCguAccepted(settings.filigran_chatbot_ai_cgu_status === 'enabled' ? 1 : 0);
    manager.setIsOrganizationSegregationEnabled(settings.platform_organization ? 1 : 0);
    manager.setIsXtmHubRegistered(settings.xtm_hub_registration_status === 'registered' ? 1 : 0);
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
    // Breakdown by catalog identity (see computeActiveConnectorsByIdentity):
    // composer-managed connectors resolve to the catalog contract slug
    // through their stored container image; manually registered connectors
    // fall back to their registered name, flagged managed=false.
    const contractsByImage = await getSupportedContractsByImage();
    manager.setActiveConnectorsByIdentity(computeActiveConnectorsByIdentity(activeConnectors, contractsByImage));
    // endregion

    // region Roles with draft capability information
    const rolesWithCapabilityInDraft = await findRolesWithCapabilityInDraft(context, TELEMETRY_MANAGER_USER);
    manager.setRolesWithCapabilityInDraftCount(rolesWithCapabilityInDraft.length);
    // endregion

    // region Draft information
    const draftWorkspaces = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_DRAFT_WORKSPACE);
    manager.setDraftCount(draftWorkspaces.length);
    // endregion

    // region Workbenches information
    const pendingFileFilter = {
      mode: FilterMode.And,
      filters: [{ key: ['internal_id'], values: ['import/pending'], operator: 'starts_with' }],
      filterGroups: [],
    };
    const workbenchesCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { filters: pendingFileFilter, types: [ENTITY_TYPE_INTERNAL_FILE] });
    manager.setWorkbenchCount(workbenchesCount);
    // endregion

    // region PIR information
    const pirs = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_PIR);
    manager.setPirCount(pirs.length);
    // endregion

    // region History retention rule status
    const retentionRules = await listRules(context, TELEMETRY_MANAGER_USER);
    const hasActiveHistoryRetentionRule = retentionRules.some((rule) => rule.scope === 'history' && rule.active);
    manager.setIsHistoryRetentionRuleActive(hasActiveHistoryRetentionRule ? 1 : 0);
    const hasActiveActivityRetentionRule = retentionRules.some((rule) => rule.scope === 'activity' && rule.active);
    manager.setIsActivityRetentionRuleActive(hasActiveActivityRetentionRule ? 1 : 0);
    // endregion

    // region Activity status
    const hasActivityListeners = (settings.activity_listeners_ids ?? []).length > 0;
    manager.setIsActivityEnabled(hasActivityListeners ? 1 : 0);
    // endregion

    manager.setSsoLocalStrategyEnabled(settings.local_auth?.enabled ? 1 : 0);
    manager.setSsoCertStrategyEnabled(settings.cert_auth?.enabled ? 1 : 0);
    manager.setSsoHeaderStrategyEnabled(settings.headers_auth?.enabled ? 1 : 0);
    // region SSO providers configuration
    manager.setSsoOpenidStrategyEnabled(isStrategyActivated(EnvStrategyType.STRATEGY_OPENID) ? 1 : 0);
    manager.setSsoLDAPStrategyEnabled(isStrategyActivated(EnvStrategyType.STRATEGY_LDAP) ? 1 : 0);
    manager.setSsoSAMLStrategyEnabled(isStrategyActivated(EnvStrategyType.STRATEGY_SAML) ? 1 : 0);
    manager.setSsoAuthZeroStrategyEnabled(isStrategyActivated(EnvStrategyType.STRATEGY_AUTH0) ? 1 : 0);
    manager.setSsoFacebookStrategyEnabled(isStrategyActivated(EnvStrategyType.STRATEGY_FACEBOOK) ? 1 : 0);
    manager.setSsoGoogleStrategyEnabled(isStrategyActivated(EnvStrategyType.STRATEGY_GOOGLE) ? 1 : 0);
    manager.setSsoGithubStrategyEnabled(isStrategyActivated(EnvStrategyType.STRATEGY_GITHUB) ? 1 : 0);
    // endregion SSO providers

    // region Security Coverages
    const securityCoveragesCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, {
      types: [ENTITY_TYPE_SECURITY_COVERAGE],
    });
    manager.setSecurityCoveragesCount(securityCoveragesCount);
    // endregion

    // region Shared saved filters
    const savedFilters = await fullEntitiesList<BasicStoreEntitySavedFilter>(
      context,
      TELEMETRY_MANAGER_USER,
      [ENTITY_TYPE_SAVED_FILTER],
      { includeAuthorities: true, baseData: true, baseFields: ['creator_id', 'restricted_members'] },
    );
    const sharedSavedFilters = savedFilters.filter((f) => isSavedFilterShared(f));
    manager.setSharedSavedFiltersCount(sharedSavedFilters.length);
    // endregion

    // region Knowledge graph scale
    // The three independent ES queries run in parallel.
    const [knowledgeAggregation, observablesCount, relationshipsCount] = await Promise.all([
      elAggregationCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, {
        field: 'entity_type',
        types: KNOWLEDGE_OBJECT_TYPES,
        normalizeLabel: false,
      }),
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_CYBER_OBSERVABLES, {}),
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_CORE_RELATIONSHIPS, {}),
    ]);
    const knowledgeItems: DimensionalGaugeItem[] = knowledgeAggregation
      .map(({ label, count }) => ({ value: count, attributes: { type: String(label).toLowerCase() } }));
    knowledgeItems.push({ value: observablesCount, attributes: { type: 'observable' } });
    knowledgeItems.push({ value: relationshipsCount, attributes: { type: 'relationship' } });
    manager.setKnowledgeObjectsByType(knowledgeItems);
    // endregion

    // region Ingestion adoption
    // Total/running counts are computed with ES count queries (no document
    // fetching) and the independent queries run in parallel. Zero-valued
    // datapoints are kept so "configured but stopped" adoption states stay
    // visible.
    const ingesterDefinitions: [string, string][] = [
      [ENTITY_TYPE_INGESTION_RSS, 'rss'],
      [ENTITY_TYPE_INGESTION_TAXII, 'taxii'],
      [ENTITY_TYPE_INGESTION_TAXII_COLLECTION, 'taxii-collection'],
      [ENTITY_TYPE_INGESTION_CSV, 'csv'],
      [ENTITY_TYPE_INGESTION_JSON, 'json'],
    ];
    const ingesterBreakdowns = await Promise.all(ingesterDefinitions.map(async ([entityType, label]) => {
      const [totalCount, runningCount] = await Promise.all([
        elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [entityType] }),
        elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [entityType], filters: booleanTrueFilter('ingestion_running') }),
      ]);
      return [
        { value: runningCount, attributes: { type: label, running: 'true' } },
        { value: Math.max(totalCount - runningCount, 0), attributes: { type: label, running: 'false' } },
      ];
    }));
    manager.setIngestersByType(ingesterBreakdowns.flat());
    const synchronizersCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_SYNC] });
    manager.setSynchronizersCount(synchronizersCount);
    // endregion

    // region Data sharing adoption
    const dataShareItems: DimensionalGaugeItem[] = [];
    const buildPublicBreakdown = (type: string, totalCount: number, publicCount: number) => {
      dataShareItems.push({ value: publicCount, attributes: { type, public: 'true' } });
      dataShareItems.push({ value: Math.max(totalCount - publicCount, 0), attributes: { type, public: 'false' } });
    };
    // Live streams and public dashboards are already held in the entity cache;
    // feeds and TAXII collections are counted with ES count queries (they are
    // not cached and can be numerous on large deployments).
    const liveStreams = await getEntitiesListFromCache<DataShareLike>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_STREAM_COLLECTION);
    buildPublicBreakdown('live_stream', liveStreams.length, liveStreams.filter((stream) => stream.stream_public === true).length);
    const [feedsCount, publicFeedsCount, taxiiCollectionsCount, publicTaxiiCollectionsCount] = await Promise.all([
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_FEED] }),
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_FEED], filters: booleanTrueFilter('feed_public') }),
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_TAXII_COLLECTION] }),
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_TAXII_COLLECTION], filters: booleanTrueFilter('taxii_public') }),
    ]);
    buildPublicBreakdown('feed', feedsCount, publicFeedsCount);
    buildPublicBreakdown('taxii_collection', taxiiCollectionsCount, publicTaxiiCollectionsCount);
    // Public dashboards are anonymous-access by nature once enabled.
    const publicDashboards = await getEntitiesListFromCache<DataShareLike>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_PUBLIC_DASHBOARD);
    buildPublicBreakdown('public_dashboard', publicDashboards.length, publicDashboards.filter((dashboard) => dashboard.enabled === true).length);
    manager.setDataSharesByType(dataShareItems);
    // endregion

    // region Automation adoption (playbooks and inference rules)
    // The entity cache only holds RUNNING playbooks; the total comes from the
    // index so the stopped count is total minus running.
    const runningPlaybooks = await getEntitiesListFromCache(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_PLAYBOOK);
    const totalPlaybooksCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_PLAYBOOK] });
    manager.setPlaybooksItems([
      { value: runningPlaybooks.length, attributes: { running: 'true' } },
      { value: Math.max(totalPlaybooksCount - runningPlaybooks.length, 0), attributes: { running: 'false' } },
    ]);
    const rules = await getEntitiesListFromCache<BasicStoreEntity & { active?: boolean }>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_RULE);
    manager.setInferenceRulesActiveCount(rules.filter((rule) => rule.active === true).length);
    // endregion

    // region Notifications adoption
    const triggers = await getEntitiesListFromCache<BasicStoreEntity & { trigger_type?: string }>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_TRIGGER);
    const liveTriggersCount = triggers.filter((trigger) => trigger.trigger_type === 'live').length;
    manager.setTriggersByType([
      { value: liveTriggersCount, attributes: { type: 'live' } },
      { value: triggers.length - liveTriggersCount, attributes: { type: 'digest' } },
    ]);
    const notifiers = await getEntitiesListFromCache<BasicStoreEntity & { notifier_connector_id?: string }>(context, TELEMETRY_MANAGER_USER, ENTITY_TYPE_NOTIFIER);
    const notifierConnectorLabel = (connectorId?: string) => {
      if (connectorId === NOTIFIER_CONNECTOR_EMAIL || connectorId === NOTIFIER_CONNECTOR_SIMPLIFIED_EMAIL) return 'email';
      if (connectorId === NOTIFIER_CONNECTOR_WEBHOOK) return 'webhook';
      if (connectorId === NOTIFIER_CONNECTOR_UI) return 'ui';
      return 'other';
    };
    const notifierItems = new Map<string, DimensionalGaugeItem>();
    ['email', 'webhook', 'ui', 'other'].forEach((connector) => notifierItems.set(connector, { value: 0, attributes: { connector } }));
    notifiers.forEach((notifier) => {
      const item = notifierItems.get(notifierConnectorLabel(notifier.notifier_connector_id));
      if (item) item.value += 1;
    });
    manager.setNotifiersByConnector(Array.from(notifierItems.values()));
    // endregion

    // region RBAC scale
    // The three independent ES count queries run in parallel.
    const [groupsCount, rolesCount, organizationsCount] = await Promise.all([
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_GROUP] }),
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_ROLE] }),
      elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_STIX_DOMAIN_OBJECTS, { types: ['Organization'] }),
    ]);
    manager.setGroupsCount(groupsCount);
    manager.setRolesCount(rolesCount);
    manager.setOrganizationsCount(organizationsCount);
    // endregion

    // region File indexing
    const managerConfigurations = await getEntitiesListFromCache<BasicStoreEntity & { manager_id?: string; manager_running?: boolean }>(
      context,
      TELEMETRY_MANAGER_USER,
      ENTITY_TYPE_MANAGER_CONFIGURATION,
    );
    const fileIndexConfiguration = managerConfigurations.find((configuration) => configuration.manager_id === 'FILE_INDEX_MANAGER');
    manager.setIsFileIndexingEnabled(fileIndexConfiguration?.manager_running === true ? 1 : 0);
    const indexedFilesCount = await elCount(context, TELEMETRY_MANAGER_USER, READ_INDEX_FILES, {});
    manager.setIndexedFilesCount(indexedFilesCount);
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
    const capabilitiesInDraftUpdatedCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_CAPABILITIES_IN_DRAFT_UPDATED);
    manager.setCapabilitiesInDraftUpdatedCount(capabilitiesInDraftUpdatedCountInRedis);
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
    const decayRuleCreationCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_DECAY_RULE_CREATION);
    manager.setDecayRuleCreationCount(decayRuleCreationCountInRedis);
    const customViewCreatedCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_CUSTOM_VIEW_CREATED);
    manager.setCustomViewCreatedCount(customViewCreatedCountInRedis);
    const customViewEnabledCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_CUSTOM_VIEW_ENABLED);
    manager.setCustomViewEnabledCount(customViewEnabledCountInRedis);
    const sharedSavedFiltersPermissionChangesCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_SAVED_FILTER_PERMISSION_CHANGES);
    manager.setSharedSavedFiltersPermissionChangesCount(sharedSavedFiltersPermissionChangesCountInRedis);
    const workflowPublishCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_WORKFLOW_PUBLISH);
    manager.setWorkflowPublishCount(workflowPublishCountInRedis);
    const chatbotMessageCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_CHATBOT_MESSAGE);
    manager.setChatbotMessageCount(chatbotMessageCountInRedis);
    const aiInsightItems: DimensionalGaugeItem[] = [];
    for (let cacheIndex = 0; cacheIndex < AI_INSIGHT_CACHE_STATES.length; cacheIndex += 1) {
      const cache = AI_INSIGHT_CACHE_STATES[cacheIndex];
      const value = await redisGetTelemetry(`${TELEMETRY_GAUGE_AI_INSIGHT_REQUEST}:${cache}`);
      aiInsightItems.push({ value, attributes: { cache } });
    }
    manager.setAiInsightRequestItems(aiInsightItems);
    const askAiItems: DimensionalGaugeItem[] = [];
    for (let featureIndex = 0; featureIndex < ASK_AI_FEATURES.length; featureIndex += 1) {
      const feature = ASK_AI_FEATURES[featureIndex];
      const value = await redisGetTelemetry(`${TELEMETRY_GAUGE_ASK_AI_QUERY}:${feature}`);
      askAiItems.push({ value, attributes: { feature } });
    }
    manager.setAskAiQueryItems(askAiItems);
    const xtmAgentItems: DimensionalGaugeItem[] = [];
    for (let channelIndex = 0; channelIndex < XTM_AGENT_CHANNELS.length; channelIndex += 1) {
      const channel = XTM_AGENT_CHANNELS[channelIndex];
      const value = await redisGetTelemetry(`${TELEMETRY_GAUGE_XTM_AGENT_CALL}:${channel}`);
      xtmAgentItems.push({ value, attributes: { channel } });
    }
    manager.setXtmAgentCallItems(xtmAgentItems);
    const playbookAiAgentRunCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_PLAYBOOK_AI_AGENT_RUN);
    manager.setPlaybookAiAgentRunCount(playbookAiAgentRunCountInRedis);
    const playbookExecutionCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_PLAYBOOK_EXECUTION);
    manager.setPlaybookExecutionCount(playbookExecutionCountInRedis);
    const notificationSentItems: DimensionalGaugeItem[] = [];
    for (let channelIndex = 0; channelIndex < NOTIFICATION_CHANNELS.length; channelIndex += 1) {
      const channel = NOTIFICATION_CHANNELS[channelIndex];
      const value = await redisGetTelemetry(`${TELEMETRY_GAUGE_NOTIFICATION_SENT}:${channel}`);
      notificationSentItems.push({ value, attributes: { channel } });
    }
    manager.setNotificationSentItems(notificationSentItems);
    const exportGeneratedCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_EXPORT_GENERATED);
    manager.setExportGeneratedCount(exportGeneratedCountInRedis);
    const ingestionObjectsProcessedCountInRedis = await redisGetTelemetry(TELEMETRY_GAUGE_INGESTION_OBJECTS_PROCESSED);
    manager.setIngestionObjectsProcessedCount(ingestionObjectsProcessedCountInRedis);
    // end region Telemetry user events

    logApp.debug(`[TELEMETRY] Fetching telemetry data successfully in ${new Date().getTime() - startTime} ms`);
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

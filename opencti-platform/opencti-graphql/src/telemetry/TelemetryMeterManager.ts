import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { ObservableResult } from '@opentelemetry/api';
import { ValueType } from '@opentelemetry/api';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

// One datapoint of a multi-dimensional gauge: a value observed with a set of
// OTLP datapoint attributes (labels).
export interface DimensionalGaugeItem {
  value: number;
  attributes: Record<string, string>;
}

// Normalize the deployment tags configured via telemetry_manager:tags
// (TELEMETRY_MANAGER__TAGS): split on ",", trim, lowercase, drop empties,
// dedupe, sort, re-join. Shared Filigran contract (same normalization in
// XTM One and OpenAEV) so an identical tag set always produces the identical
// string in the analytics warehouse.
export const normalizeTelemetryTags = (rawTags: string | null | undefined): string => {
  const tags = new Set(
    (rawTags ?? '')
      .split(',')
      .map((tag) => tag.trim().toLowerCase())
      .filter((tag) => tag.length > 0),
  );
  return Array.from(tags).sort().join(',');
};

// The connector fields the identity breakdown relies on (structural subset of
// BasicStoreEntityConnector, kept minimal so the pure computation stays
// unit-testable without the store type transitive closure).
export interface ConnectorIdentitySource {
  catalog_id?: string | null;
  manager_contract_image?: string | null;
  name?: string | null;
  connector_type?: string | null;
}

// Reduce a container image reference to its repository path: drop any digest
// (@sha256:...), any tag (":x" after the last "/") and the registry hostname.
// Per the Docker reference grammar the first path component is a registry
// host iff it contains "." or ":" or is exactly "localhost" - bare Docker Hub
// namespaces (e.g. "opencti/connector-mitre") are therefore preserved. The
// registry hostname is the only deployment-infrastructure detail in an image
// reference, so stripping it keeps the connector identity exportable without
// leaking where the image is hosted.
export const stripImageToRepositoryPath = (imageReference: string | null | undefined): string => {
  const reference = (imageReference ?? '').trim().toLowerCase();
  if (reference.length === 0) {
    return '';
  }
  const withoutDigest = reference.split('@')[0];
  const lastSlash = withoutDigest.lastIndexOf('/');
  const lastColon = withoutDigest.lastIndexOf(':');
  const withoutTag = lastColon > lastSlash ? withoutDigest.slice(0, lastColon) : withoutDigest;
  const segments = withoutTag.split('/').filter((segment) => segment.length > 0);
  // Strip the registry host even when it is the ONLY segment (host-only,
  // repository-less reference): returning it would leak the hostname the
  // whole helper exists to withhold. Callers treat '' as "no usable identity".
  if (segments.length > 0 && (segments[0].includes('.') || segments[0].includes(':') || segments[0] === 'localhost')) {
    segments.shift();
  }
  return segments.join('/');
};

// Breakdown of active connectors by catalog identity: composer-managed
// connectors resolve to the exact catalog contract slug through their stored
// container image (the user-set connector name is irrelevant). When the
// stored image is not in the catalog (custom contract, removed contract,
// private catalog on an on-premise deployment), the registry-stripped
// repository path of the image is exported instead so those deployments stay
// visible - the raw reference (and thus a private registry hostname) never
// leaves the platform. Manually registered connectors have no catalog
// reference, so their trimmed/lowercased registered name is the best
// available identity, flagged managed=false.
export const computeActiveConnectorsByIdentity = (
  activeConnectors: ConnectorIdentitySource[],
  contractsByImage: ReadonlyMap<string, { slug: string }>,
): DimensionalGaugeItem[] => {
  const connectorsByIdentity = new Map<string, DimensionalGaugeItem>();
  activeConnectors.forEach((connector) => {
    const isManaged = (connector.catalog_id ?? '').length > 0;
    const slug = isManaged
      ? (contractsByImage.get(connector.manager_contract_image ?? '')?.slug ?? stripImageToRepositoryPath(connector.manager_contract_image))
      : (connector.name ?? '').trim().toLowerCase();
    if (slug.length === 0) {
      return;
    }
    const attributes = { slug, managed: isManaged ? 'true' : 'false', type: connector.connector_type ?? '' };
    // JSON-encode the key components: manual connector names are freeform, so
    // a naive separator-joined key could collide across identities.
    const identityKey = JSON.stringify([attributes.slug, attributes.managed, attributes.type]);
    const existingItem = connectorsByIdentity.get(identityKey);
    if (existingItem) {
      existingItem.value += 1;
    } else {
      connectorsByIdentity.set(identityKey, { value: 1, attributes });
    }
  });
  return Array.from(connectorsByIdentity.values());
};

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  // Is enterprise Edition is activated
  isEEActivated = 0;

  // Cluster number of instances
  instancesCount = 0;

  // Number of users in the platform (except service account)
  usersCount = 0;

  // Number of users in the platform
  serviceAccountCount = 0;

  // Number of active connectors
  activeConnectorsCount = 0;

  // Active connectors broken down by catalog identity (slug, managed, type).
  // Composer-managed connectors carry the exact catalog contract slug; manual
  // connectors fall back to their registered name (managed=false).
  activeConnectorsByIdentity: DimensionalGaugeItem[] = [];

  disseminationCount = 0;

  rolesWithCapabilityInDraftCount = 0;

  capabilitiesInDraftUpdatedCount = 0;

  // Number of active drafts
  draftCount = 0;

  draftCreationCount = 0;

  draftValidationCount = 0;

  // Number of active workbenches
  workbenchCount = 0;

  workbenchUploadCount = 0;

  workbenchDraftConvertionCount = 0;

  workbenchValidationCount = 0;

  // Number of NLQ query call
  nlqQueryCount = 0;

  // Number of RFI of request access type that are created
  requestAccessCreationCount = 0;

  // Number of User turned into Service Account
  userIntoServiceAccountCount = 0;

  // Number of Service Account turned into Service
  serviceAccountIntoUserCount = 0;

  // Number of email sent
  userEmailSendCount = 0;

  // Number of background task with scope User
  userBackgroundTaskCount = 0;

  // Number of email templates created
  emailTemplateCreatedCount = 0;

  // Number of clicks on Forgot Password
  forgotPasswordCount = 0;

  // Number of PIR
  pirCount = 0;

  // Number of connectors deployed
  connectorDeployedCount = 0;

  // +1 when a user that login into application, does not count token authentication
  userLoginCount = 0;

  // Number of form intakes created
  formIntakeCreatedCount = 0;

  // Number of form intakes updated
  formIntakeUpdatedCount = 0;

  // Number of form intakes deleted
  formIntakeDeletedCount = 0;

  // Number of form intakes submitted
  formIntakeSubmittedCount = 0;

  // Number security coverages
  securityCoveragesCount = 0;

  // Number of decay rules created
  decayRuleCreationCount = 0;

  // Whether the history retention rule is active on the platform (0 or 1)
  isHistoryRetentionRuleActive = 0;

  // Whether the activity retention rule is active on the platform (0 or 1)
  isActivityRetentionRuleActive = 0;

  // Whether activity is enabled on the platform (0 or 1) - has activity listeners configured
  isActivityEnabled = 0;

  // Region Telemetry on SSO providers usage
  // True when the strategy is configured and enabled. False if not.
  ssoLocalStrategyEnabled = 0;

  ssoOpenidStrategyEnabled = 0;

  ssoLDAPStrategyEnabled = 0;

  ssoSAMLStrategyEnabled = 0;

  ssoAuthZeroStrategyEnabled = 0;

  ssoCertStrategyEnabled = 0;

  ssoHeaderStrategyEnabled = 0;

  ssoFacebookStrategyEnabled = 0;

  ssoGoogleStrategyEnabled = 0;

  ssoGithubStrategyEnabled = 0;

  customViewCreatedCount = 0;

  customViewEnabledCount = 0;

  sharedSavedFiltersCount = 0;

  workflowPublishCount = 0;

  // endregion providers usage

  // region AI usage (backend-agnostic: no legacy/xtm_one dimension anywhere)
  // Number of chatbot messages sent (legacy Flowise and XTM One combined)
  chatbotMessageCount = 0;

  // AI Insights requests broken down by cache state (hit | miss)
  aiInsightRequestItems: DimensionalGaugeItem[] = [];

  // Ask AI queries broken down by feature (fix_spelling, summarize, ...)
  askAiQueryItems: DimensionalGaugeItem[] = [];

  // Direct XTM One agent calls broken down by channel (direct | direct_files)
  xtmAgentCallItems: DimensionalGaugeItem[] = [];

  // Number of playbook AI agent component runs
  playbookAiAgentRunCount = 0;

  // Built-in LLM configuration state, with the provider type as dimension
  isAiEnabledItems: DimensionalGaugeItem[] = [];

  // Segmentation keys for before/after XTM One adoption analysis
  isXtmOneConfigured = 0;

  isChatbotCguAccepted = 0;
  // endregion AI usage

  // region Product adoption
  // Knowledge graph scale broken down by curated entity type
  knowledgeObjectsByType: DimensionalGaugeItem[] = [];

  // Built-in ingesters broken down by type (rss | taxii | ...) and running state
  ingestersByType: DimensionalGaugeItem[] = [];

  // Data sharing surfaces broken down by type and public (anonymous) state
  dataSharesByType: DimensionalGaugeItem[] = [];

  // Playbooks broken down by running state (EE)
  playbooksItems: DimensionalGaugeItem[] = [];

  // Number of activated inference rules
  inferenceRulesActiveCount = 0;

  // Notification triggers broken down by type (live | digest)
  triggersByType: DimensionalGaugeItem[] = [];

  // Notifiers broken down by connector (email | webhook | ui | other)
  notifiersByConnector: DimensionalGaugeItem[] = [];

  // RBAC scale
  groupsCount = 0;

  rolesCount = 0;

  organizationsCount = 0;

  // Number of OpenCTI-to-OpenCTI synchronizers
  synchronizersCount = 0;

  // Whether organization segregation is configured (EE)
  isOrganizationSegregationEnabled = 0;

  // Whether the file indexing manager is running
  isFileIndexingEnabled = 0;

  // Whether the platform is registered on XTM Hub
  isXtmHubRegistered = 0;

  // Number of indexed files
  indexedFilesCount = 0;

  // Number of playbook executions started
  playbookExecutionCount = 0;

  // Notifications sent broken down by channel (email | webhook | ui)
  notificationSentItems: DimensionalGaugeItem[] = [];

  // Number of export generations requested
  exportGeneratedCount = 0;

  // Number of objects processed by completed works (ingestion volume proxy)
  ingestionObjectsProcessedCount = 0;
  // endregion Product adoption

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  async shutdown() {
    return this.meterProvider.shutdown();
  }

  setIsEEActivated(EE: number) {
    this.isEEActivated = EE;
  }

  setSsoLocalStrategyEnabled(enabled: number) {
    this.ssoLocalStrategyEnabled = enabled;
  }

  setSsoOpenidStrategyEnabled(enabled: number) {
    this.ssoOpenidStrategyEnabled = enabled;
  }

  setSsoLDAPStrategyEnabled(enabled: number) {
    this.ssoLDAPStrategyEnabled = enabled;
  }

  setSsoSAMLStrategyEnabled(enabled: number) {
    this.ssoSAMLStrategyEnabled = enabled;
  }

  setSsoAuthZeroStrategyEnabled(enabled: number) {
    this.ssoAuthZeroStrategyEnabled = enabled;
  }

  setSsoCertStrategyEnabled(enabled: number) {
    this.ssoCertStrategyEnabled = enabled;
  }

  setSsoHeaderStrategyEnabled(enabled: number) {
    this.ssoHeaderStrategyEnabled = enabled;
  }

  setSsoFacebookStrategyEnabled(enabled: number) {
    this.ssoFacebookStrategyEnabled = enabled;
  }

  setSsoGoogleStrategyEnabled(enabled: number) {
    this.ssoGoogleStrategyEnabled = enabled;
  }

  setSsoGithubStrategyEnabled(enabled: number) {
    this.ssoGithubStrategyEnabled = enabled;
  }

  setInstancesCount(n: number) {
    this.instancesCount = n;
  }

  setUsersCount(n: number) {
    this.usersCount = n;
  }

  setServiceAccountsCount(n: number) {
    this.serviceAccountCount = n;
  }

  setActiveConnectorsCount(n: number) {
    this.activeConnectorsCount = n;
  }

  setActiveConnectorsByIdentity(items: DimensionalGaugeItem[]) {
    this.activeConnectorsByIdentity = items;
  }

  setDisseminationCount(n: number) {
    this.disseminationCount = n;
  }

  setRolesWithCapabilityInDraftCount(n: number) {
    this.rolesWithCapabilityInDraftCount = n;
  }

  setCapabilitiesInDraftUpdatedCount(n: number) {
    this.capabilitiesInDraftUpdatedCount = n;
  }

  setDraftCount(n: number) {
    this.draftCount = n;
  }

  setDraftCreationCount(n: number) {
    this.draftCreationCount = n;
  }

  setDraftValidationCount(n: number) {
    this.draftValidationCount = n;
  }

  setWorkbenchCount(n: number) {
    this.workbenchCount = n;
  }

  setWorkbenchUploadCount(n: number) {
    this.workbenchUploadCount = n;
  }

  setWorkbenchDraftConvertionCount(n: number) {
    this.workbenchDraftConvertionCount = n;
  }

  setWorkbenchValidationCount(n: number) {
    this.workbenchValidationCount = n;
  }

  setNlqQueryCount(n: number) {
    this.nlqQueryCount = n;
  }

  setRequestAccessCreatedCount(n: number) {
    this.requestAccessCreationCount = n;
  }

  setUserIntoServiceAccountCount(n: number) {
    this.userIntoServiceAccountCount = n;
  }

  setServiceAccountIntoUserCount(n: number) {
    this.serviceAccountIntoUserCount = n;
  }

  setUserEmailSendCount(n: number) {
    this.userEmailSendCount = n;
  }

  setUserBackgroundTaskCount(n: number) {
    this.userBackgroundTaskCount = n;
  }

  setEmailTemplateCreatedCount(n: number) {
    this.emailTemplateCreatedCount = n;
  }

  setForgotPasswordCount(n: number) {
    this.forgotPasswordCount = n;
  }

  setPirCount(n: number) {
    this.pirCount = n;
  }

  setConnectorDeployedCount(n: number) {
    this.connectorDeployedCount = n;
  }

  setUserLoginCount(n: number) {
    this.userLoginCount = n;
  }

  setFormIntakeCreatedCount(n: number) {
    this.formIntakeCreatedCount = n;
  }

  setFormIntakeUpdatedCount(n: number) {
    this.formIntakeUpdatedCount = n;
  }

  setFormIntakeDeletedCount(n: number) {
    this.formIntakeDeletedCount = n;
  }

  setFormIntakeSubmittedCount(n: number) {
    this.formIntakeSubmittedCount = n;
  }

  setSecurityCoveragesCount(n: number) {
    this.securityCoveragesCount = n;
  }

  setDecayRuleCreationCount(n: number) {
    this.decayRuleCreationCount = n;
  }

  setIsHistoryRetentionRuleActive(n: number) {
    this.isHistoryRetentionRuleActive = n;
  }

  setIsActivityRetentionRuleActive(n: number) {
    this.isActivityRetentionRuleActive = n;
  }

  setIsActivityEnabled(n: number) {
    this.isActivityEnabled = n;
  }

  setCustomViewCreatedCount(n: number) {
    this.customViewCreatedCount = n;
  }

  setCustomViewEnabledCount(n: number) {
    this.customViewEnabledCount = n;
  }

  setSharedSavedFiltersCount(n: number) {
    this.sharedSavedFiltersCount = n;
  }

  setWorkflowPublishCount(n: number) {
    this.workflowPublishCount = n;
  }

  setChatbotMessageCount(n: number) {
    this.chatbotMessageCount = n;
  }

  setAiInsightRequestItems(items: DimensionalGaugeItem[]) {
    this.aiInsightRequestItems = items;
  }

  setAskAiQueryItems(items: DimensionalGaugeItem[]) {
    this.askAiQueryItems = items;
  }

  setXtmAgentCallItems(items: DimensionalGaugeItem[]) {
    this.xtmAgentCallItems = items;
  }

  setPlaybookAiAgentRunCount(n: number) {
    this.playbookAiAgentRunCount = n;
  }

  setIsAiEnabledItems(items: DimensionalGaugeItem[]) {
    this.isAiEnabledItems = items;
  }

  setIsXtmOneConfigured(n: number) {
    this.isXtmOneConfigured = n;
  }

  setIsChatbotCguAccepted(n: number) {
    this.isChatbotCguAccepted = n;
  }

  setKnowledgeObjectsByType(items: DimensionalGaugeItem[]) {
    this.knowledgeObjectsByType = items;
  }

  setIngestersByType(items: DimensionalGaugeItem[]) {
    this.ingestersByType = items;
  }

  setDataSharesByType(items: DimensionalGaugeItem[]) {
    this.dataSharesByType = items;
  }

  setPlaybooksItems(items: DimensionalGaugeItem[]) {
    this.playbooksItems = items;
  }

  setInferenceRulesActiveCount(n: number) {
    this.inferenceRulesActiveCount = n;
  }

  setTriggersByType(items: DimensionalGaugeItem[]) {
    this.triggersByType = items;
  }

  setNotifiersByConnector(items: DimensionalGaugeItem[]) {
    this.notifiersByConnector = items;
  }

  setGroupsCount(n: number) {
    this.groupsCount = n;
  }

  setRolesCount(n: number) {
    this.rolesCount = n;
  }

  setOrganizationsCount(n: number) {
    this.organizationsCount = n;
  }

  setSynchronizersCount(n: number) {
    this.synchronizersCount = n;
  }

  setIsOrganizationSegregationEnabled(n: number) {
    this.isOrganizationSegregationEnabled = n;
  }

  setIsFileIndexingEnabled(n: number) {
    this.isFileIndexingEnabled = n;
  }

  setIsXtmHubRegistered(n: number) {
    this.isXtmHubRegistered = n;
  }

  setIndexedFilesCount(n: number) {
    this.indexedFilesCount = n;
  }

  setPlaybookExecutionCount(n: number) {
    this.playbookExecutionCount = n;
  }

  setNotificationSentItems(items: DimensionalGaugeItem[]) {
    this.notificationSentItems = items;
  }

  setExportGeneratedCount(n: number) {
    this.exportGeneratedCount = n;
  }

  setIngestionObjectsProcessedCount(n: number) {
    this.ingestionObjectsProcessedCount = n;
  }

  registerGauge(name: string, description: string, observer: string, opts: {
    unit?: string;
    valueType?: ValueType;
  } = {}) {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    const gaugeOptions = { description, unit: opts.unit ?? 'count', valueType: opts.valueType ?? ValueType.INT };
    const activeUsersCountGauge = meter.createObservableGauge(`opencti_${name}`, gaugeOptions);
    activeUsersCountGauge.addCallback((observableResult: ObservableResult) => {
      /* eslint-disable @typescript-eslint/ban-ts-comment */
      // @ts-ignore
      observableResult.observe(this[observer]);
    });
  }

  // Multi-dimensional gauge: the observed property holds a list of
  // DimensionalGaugeItem, each exported as one datapoint with its own OTLP
  // attributes (labels).
  registerDimensionalGauge(name: string, description: string, observer: string, opts: {
    unit?: string;
    valueType?: ValueType;
  } = {}) {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    const gaugeOptions = { description, unit: opts.unit ?? 'count', valueType: opts.valueType ?? ValueType.INT };
    const dimensionalGauge = meter.createObservableGauge(`opencti_${name}`, gaugeOptions);
    dimensionalGauge.addCallback((observableResult: ObservableResult) => {
      const items = (this as unknown as Record<string, unknown>)[observer];
      // Guard against a mis-registered observer (unset property or scalar
      // field): observing nothing is better than throwing inside the OTLP
      // collection callback and breaking the whole export cycle.
      if (!Array.isArray(items)) {
        return;
      }
      (items as DimensionalGaugeItem[]).forEach((item) => observableResult.observe(item.value, item.attributes));
    });
  }

  registerFiligranTelemetry() {
    // This kind of gauge count be synchronous, waiting for opentelemetry-js 3668
    // https://github.com/open-telemetry/opentelemetry-js/issues/3668
    this.registerGauge('total_users_count', 'number of users', 'usersCount');
    this.registerGauge('total_service_account_count', 'number of service account', 'serviceAccountCount');
    this.registerGauge('total_instances_count', 'cluster number of instances', 'instancesCount');
    this.registerGauge('active_connectors_count', 'number of active connectors', 'activeConnectorsCount');
    this.registerDimensionalGauge('active_connectors_by_identity', 'active connectors broken down by catalog identity (slug, managed, type)', 'activeConnectorsByIdentity');
    this.registerGauge('is_enterprise_edition', 'enterprise Edition is activated', 'isEEActivated', { unit: 'boolean' });
    this.registerGauge('call_dissemination', 'dissemination feature usage', 'disseminationCount');
    this.registerGauge('roles_with_capability_in_draft_count', 'number of roles with capability in draft', 'rolesWithCapabilityInDraftCount');
    this.registerGauge('capabilities_in_draft_tab_loaded_count', 'number of times the capabilities in draft tab is loaded', 'capabilitiesInDraftTabLoadedCount');
    this.registerGauge('active_drafts_count', 'number of active drafts', 'draftCount');
    this.registerGauge('draft_creation_count', 'number of draft creation', 'draftCreationCount');
    this.registerGauge('draft_validation_count', 'number of draft validation', 'draftValidationCount');
    this.registerGauge('active_workbenches_count', 'number of active workbenches', 'workbenchCount');
    this.registerGauge('workbench_upload_count', 'number of workbench upload - creation and updates', 'workbenchUploadCount');
    this.registerGauge('workbench_draft_convertion_count', 'number of workbench to draft convertion', 'workbenchDraftConvertionCount');
    this.registerGauge('workbench_validation_count', 'number of workbench validation', 'workbenchValidationCount');
    this.registerGauge('call_nlq', 'NLQ feature usage', 'nlqQueryCount');
    this.registerGauge('request_access_creation_count', 'Number of RFI of request access type that are created', 'requestAccessCreationCount');
    this.registerGauge('user_into_service_account_count', 'Number of User turned into Service Account', 'userIntoServiceAccountCount');
    this.registerGauge('service_account_into_user_count', 'Number of Service Account turned into User', 'serviceAccountIntoUserCount');
    this.registerGauge('user_email_send_count', 'Number of emails sent from the platform', 'userEmailSendCount');
    this.registerGauge('user_background_task_count', 'Number of background tasks on User scope', 'userBackgroundTaskCount');
    this.registerGauge('email_template_created_count', 'Number of email templates created', 'emailTemplateCreatedCount');
    this.registerGauge('forgot_password_count', 'Number of clicks on Forgot Password', 'forgotPasswordCount');
    this.registerGauge('pir_count', 'number of PIRs', 'pirCount');
    this.registerGauge('connector_deployed_count', 'Number of connectors deployed via composer', 'connectorDeployedCount');
    this.registerGauge('user_login_count', 'Number of user that logs-in into application', 'userLoginCount');
    this.registerGauge('form_intake_created_count', 'Number of form intakes created', 'formIntakeCreatedCount');
    this.registerGauge('form_intake_updated_count', 'Number of form intakes updated', 'formIntakeUpdatedCount');
    this.registerGauge('form_intake_deleted_count', 'Number of form intakes deleted', 'formIntakeDeletedCount');
    this.registerGauge('form_intake_submitted_count', 'Number of form intakes submitted', 'formIntakeSubmittedCount');
    this.registerGauge('security_coverages_count', 'Number of security coverages', 'securityCoveragesCount');
    this.registerGauge('decay_rule_creation_count', 'Number of decay rules created', 'decayRuleCreationCount');
    this.registerGauge('is_history_retention_rule_active', 'Whether the history retention rule is active on the platform', 'isHistoryRetentionRuleActive', { unit: 'boolean' });
    this.registerGauge('is_activity_retention_rule_active', 'Whether the activity retention rule is active on the platform', 'isActivityRetentionRuleActive', { unit: 'boolean' });
    this.registerGauge('is_activity_enabled', 'Whether activity is enabled on the platform (has activity listeners)', 'isActivityEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_local_strategy_enabled', 'LocalStrategy is configured and enabled', 'ssoLocalStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_openid_strategy_enabled', 'OpenidStrategy is configured and enabled', 'ssoOpenidStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_ldap_strategy_enabled', 'LDAPStrategy is configured and enabled', 'ssoLDAPStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_saml_strategy_enabled', 'SAMLStrategy is configured and enabled', 'ssoSAMLStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_authzero_strategy_enabled', 'AuthZeroStrategy is configured and enabled', 'ssoAuthZeroStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_cert_strategy_enabled', 'CertStrategy is configured and enabled', 'ssoCertStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_header_strategy_enabled', 'HeaderStrategy is configured and enabled', 'ssoHeaderStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_facebook_strategy_enabled', 'FacebookStrategy is configured and enabled', 'ssoFacebookStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_google_strategy_enabled', 'GoogleStrategy is configured and enabled', 'ssoGoogleStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('is_sso_github_strategy_enabled', 'GithubStrategy is configured and enabled', 'ssoGithubStrategyEnabled', { unit: 'boolean' });
    this.registerGauge('custom_view_created_count', 'Number of custom views created', 'customViewCreatedCount');
    this.registerGauge('custom_view_enabled_count', 'Number of custom views enabled', 'customViewEnabledCount');
    this.registerGauge('shared_saved_filters_count', 'Number of saved filters with access restriction', 'sharedSavedFiltersCount');
    this.registerGauge('workflow_publish_count', 'Number of workflow definitions published', 'workflowPublishCount');
    // region AI usage (backend-agnostic counters, see telemetryManager)
    this.registerGauge('chatbot_message_count', 'Number of chatbot messages sent (legacy and XTM One combined)', 'chatbotMessageCount');
    this.registerDimensionalGauge('ai_insight_request_count', 'AI Insights requests broken down by cache state (hit, miss)', 'aiInsightRequestItems');
    this.registerDimensionalGauge('ask_ai_query_count', 'Ask AI queries broken down by feature', 'askAiQueryItems');
    this.registerDimensionalGauge('xtm_agent_call_count', 'Direct XTM One agent calls broken down by channel (direct, direct_files)', 'xtmAgentCallItems');
    this.registerGauge('playbook_ai_agent_run_count', 'Number of playbook AI agent component runs', 'playbookAiAgentRunCount');
    this.registerDimensionalGauge('is_ai_enabled', 'Built-in LLM configuration state with provider type dimension', 'isAiEnabledItems', { unit: 'boolean' });
    this.registerGauge('is_xtm_one_configured', 'XTM One is configured (url and token)', 'isXtmOneConfigured', { unit: 'boolean' });
    this.registerGauge('is_chatbot_cgu_accepted', 'Filigran chatbot AI CGU accepted', 'isChatbotCguAccepted', { unit: 'boolean' });
    // endregion
    // region Product adoption
    this.registerDimensionalGauge('knowledge_objects_by_type', 'knowledge graph scale broken down by curated entity type', 'knowledgeObjectsByType');
    this.registerDimensionalGauge('ingesters_by_type', 'built-in ingesters broken down by type and running state', 'ingestersByType');
    this.registerDimensionalGauge('data_shares_by_type', 'data sharing surfaces broken down by type and public state', 'dataSharesByType');
    this.registerDimensionalGauge('playbooks_count', 'playbooks broken down by running state', 'playbooksItems');
    this.registerGauge('inference_rules_active_count', 'number of activated inference rules', 'inferenceRulesActiveCount');
    this.registerDimensionalGauge('triggers_by_type', 'notification triggers broken down by type (live, digest)', 'triggersByType');
    this.registerDimensionalGauge('notifiers_count', 'notifiers broken down by connector (email, webhook, ui, other)', 'notifiersByConnector');
    this.registerGauge('groups_count', 'number of groups', 'groupsCount');
    this.registerGauge('roles_count', 'number of roles', 'rolesCount');
    this.registerGauge('organizations_count', 'number of organizations', 'organizationsCount');
    this.registerGauge('synchronizers_count', 'number of OpenCTI synchronizers', 'synchronizersCount');
    this.registerGauge('is_organization_segregation_enabled', 'organization segregation is configured', 'isOrganizationSegregationEnabled', { unit: 'boolean' });
    this.registerGauge('is_file_indexing_enabled', 'file indexing manager is running', 'isFileIndexingEnabled', { unit: 'boolean' });
    this.registerGauge('is_xtm_hub_registered', 'platform is registered on XTM Hub', 'isXtmHubRegistered', { unit: 'boolean' });
    this.registerGauge('indexed_files_count', 'number of indexed files', 'indexedFilesCount');
    this.registerGauge('playbook_execution_count', 'number of playbook executions started', 'playbookExecutionCount');
    this.registerDimensionalGauge('notification_sent_count', 'notifications sent broken down by channel (email, webhook, ui)', 'notificationSentItems');
    this.registerGauge('export_generated_count', 'number of export generations requested', 'exportGeneratedCount');
    this.registerGauge('ingestion_objects_processed_count', 'number of objects processed by completed works', 'ingestionObjectsProcessedCount');
    // endregion
  }
}

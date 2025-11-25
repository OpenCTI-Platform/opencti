import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { ObservableResult } from '@opentelemetry/api-metrics';
import { ValueType } from '@opentelemetry/api';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

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

  disseminationCount = 0;

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

  // endregion providers usage

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

  setDisseminationCount(n: number) {
    this.disseminationCount = n;
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

  registerGauge(name: string, description: string, observer: string, opts: {
    unit?: string,
    valueType?: ValueType
  } = {}) {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    const gaugeOptions = { description, unit: opts.unit ?? 'count', valueType: opts.valueType ?? ValueType.INT };
    const activeUsersCountGauge = meter.createObservableGauge(`opencti_${name}`, gaugeOptions,);
    activeUsersCountGauge.addCallback((observableResult: ObservableResult) => {
      /* eslint-disable @typescript-eslint/ban-ts-comment */
      // @ts-ignore
      observableResult.observe(this[observer]);
    });
  }

  registerFiligranTelemetry() {
    // This kind of gauge count be synchronous, waiting for opentelemetry-js 3668
    // https://github.com/open-telemetry/opentelemetry-js/issues/3668
    this.registerGauge('total_users_count', 'number of users', 'usersCount');
    this.registerGauge('total_service_account_count', 'number of service account', 'serviceAccountCount');
    this.registerGauge('total_instances_count', 'cluster number of instances', 'instancesCount');
    this.registerGauge('active_connectors_count', 'number of active connectors', 'activeConnectorsCount');
    this.registerGauge('is_enterprise_edition', 'enterprise Edition is activated', 'isEEActivated', { unit: 'boolean' });
    this.registerGauge('call_dissemination', 'dissemination feature usage', 'disseminationCount');
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
  }
}

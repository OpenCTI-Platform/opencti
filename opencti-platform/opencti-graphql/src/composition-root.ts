import type { ModuleDescriptor } from './modules/module-descriptor';
import { registerDefinition } from './schema/module';
import { registerEntityOverviewLayoutCustomization } from './schema/overviewLayoutCustomization-register';
import { schemaAttributesDefinition } from './schema/schema-attributes';
import { registerGraphqlSchema } from './graphql/schema';
import { registerManager } from './manager/managerModule';
import caseModule from './modules/case/case-module';
import caseTemplateModule from './modules/case/case-template/case-template-module';
import caseIncidentModule from './modules/case/case-incident/case-incident-module';
import caseRfiModule from './modules/case/case-rfi/case-rfi-module';
import caseRftModule from './modules/case/case-rft/case-rft-module';
import feedbackModule from './modules/case/feedback/feedback-module';
import entitySettingModule from './modules/entitySetting/entitySetting-module';
import workflowModule from './modules/workflow/workflow-module';
import workspaceModule from './modules/workspace/workspace-module';
import malwareAnalysisModule from './modules/malwareAnalysis/malwareAnalysis-module';
import managerConfigurationModule from './modules/managerConfiguration/managerConfiguration-module';
import notifierModule from './modules/notifier/notifier-module';
import threatActorIndividualModule from './modules/threatActorIndividual/threatActorIndividual-module';
import playbookModule from './modules/playbook/playbook-module';
import ingestionModule from './modules/ingestion/ingestion-module';
import dataSharingModule from './modules/dataSharing/dataSharing-module';
import indicatorModule from './modules/indicator/indicator-module';
import decayRuleModule from './modules/decayRule/decayRule-module';
import decayExclusionRuleModule from './modules/decayRule/exclusions/decayExclusionRule-module';
import organizationModule from './modules/organization/organization-module';
import csvMapperModule from './modules/internal/csvMapper/csvMapper-module';
import jsonMapperModule from './modules/internal/jsonMapper/jsonMapper-module';
import documentModule from './modules/internal/document/document-module';
import publicDashboardModule from './modules/publicDashboard/publicDashboard-module';
import themeModule from './modules/theme/theme-module';
import aiModule from './modules/ai/ai-module';
import deleteOperationModule from './modules/deleteOperation/deleteOperation-module';
import supportModule from './modules/support/support-module';
import exclusionListModule from './modules/exclusionList/exclusionList-module';
import smtpConfigurationModule from './modules/smtpConfiguration/smtpConfiguration-module';
import draftWorkspaceModule from './modules/draftWorkspace/draftWorkspace-module';
import fintelTemplateModule from './modules/fintelTemplate/fintelTemplate-module';
import disseminationListModule from './modules/disseminationList/disseminationList-module';
import savedFilterModule from './modules/savedFilter/savedFilter-module';
import requestAccessModule from './modules/requestAccess/requestAccess-module';
import pirModule from './modules/pir/pir-module';
import fintelDesignModule from './modules/fintelDesign/fintelDesign-module';
import securityPlatformModule from './modules/securityPlatform/securityPlatform-module';
import emailTemplateModule from './modules/emailTemplate/emailTemplate-module';
import formModule from './modules/form/form-module';
import securityCoverageModule from './modules/securityCoverage/securityCoverage-module';
import securityCoverageResultModule from './modules/securityCoverage/securityCoverageResult/securityCoverageResult-module';
import authModule from './modules/auth/auth-module';
import authenticationProviderModule from './modules/authenticationProvider/authenticationProvider-module';
import customViewModule from './modules/customView/customView-module';
import retentionRulesModule from './modules/retentionRules/retentionRules-module';
import dataSanityModule from './modules/dataSanity/dataSanity-module';
import newsFeedModule from './modules/xtm/hub/news-feed/news-feed-module';
import xtmHubModule from './modules/xtm/hub/xtm-hub-module';
import metricsModule from './modules/metrics/metrics-module';
import userModule from './modules/user/user-module';
import userMergeModule from './modules/userMerge/userMerge-module';
import reportModule from './modules/report/report-module';
import noteModule from './modules/note/note-module';
import externalReferenceModule from './modules/externalReference/externalReference-module';
import incidentModule from './modules/incident/incident-module';
import observedDataModule from './modules/observedData/observedData-module';
import stixCyberObservableModule from './modules/stixCyberObservable/stixCyberObservable-module';
import threatActorGroupModule from './modules/threatActorGroup/threatActorGroup-module';
import intrusionSetModule from './modules/intrusionSet/intrusionSet-module';
import campaignModule from './modules/campaign/campaign-module';
import malwareModule from './modules/malware/malware-module';
import toolModule from './modules/tool/tool-module';
import vulnerabilityModule from './modules/vulnerability/vulnerability-module';
import attackPatternModule from './modules/attackPattern/attackPattern-module';
import courseOfActionModule from './modules/courseOfAction/courseOfAction-module';
import customFieldModule from './modules/customField/custom-field-module';

// Modules migrated to explicit registration.
// The others still register themselves on import, through modules/index and manager/index.
export const MODULE_DESCRIPTORS: ModuleDescriptor[] = [
  caseModule,
  caseTemplateModule,
  caseIncidentModule,
  caseRfiModule,
  caseRftModule,
  feedbackModule,
  entitySettingModule,
  workflowModule,
  workspaceModule,
  malwareAnalysisModule,
  managerConfigurationModule,
  notifierModule,
  threatActorIndividualModule,
  playbookModule,
  ingestionModule,
  dataSharingModule,
  indicatorModule,
  decayRuleModule,
  decayExclusionRuleModule,
  organizationModule,
  csvMapperModule,
  jsonMapperModule,
  documentModule,
  publicDashboardModule,
  themeModule,
  aiModule,
  deleteOperationModule,
  supportModule,
  exclusionListModule,
  smtpConfigurationModule,
  draftWorkspaceModule,
  fintelTemplateModule,
  disseminationListModule,
  savedFilterModule,
  requestAccessModule,
  pirModule,
  fintelDesignModule,
  securityPlatformModule,
  emailTemplateModule,
  formModule,
  securityCoverageModule,
  securityCoverageResultModule,
  authModule,
  authenticationProviderModule,
  customViewModule,
  retentionRulesModule,
  dataSanityModule,
  newsFeedModule,
  xtmHubModule,
  metricsModule,
  userModule,
  userMergeModule,
  reportModule,
  noteModule,
  externalReferenceModule,
  incidentModule,
  observedDataModule,
  stixCyberObservableModule,
  threatActorGroupModule,
  intrusionSetModule,
  campaignModule,
  malwareModule,
  toolModule,
  vulnerabilityModule,
  attackPatternModule,
  courseOfActionModule,
  customFieldModule,
];

let modulesRegistered = false;

// Each phase runs for every module before the next phase starts: data model (overview layouts,
// attributes, then definitions), graphql schemas, managers, then init. The whole of it runs after modules/index, so a migrated definition is
// registered after the graphql of the modules still registered on import, against the order
// modules/index documents. That is safe only while nothing reads the model at import time:
// usageProtection catches an early read of types, attributes or refs, not of converters or validators.
// Must run before anything reads the schema (selectEntityType, createSchema, startAllManagers).
export const registerModules = (descriptors: ModuleDescriptor[] = MODULE_DESCRIPTORS) => {
  if (modulesRegistered) {
    return;
  }
  modulesRegistered = true;
  descriptors.forEach(({ overviewLayouts = [], attributes = [], dataModel = [] }) => {
    overviewLayouts.forEach(({ entityType, layout }) => registerEntityOverviewLayoutCustomization(entityType, layout));
    attributes.forEach((definition) => schemaAttributesDefinition.registerAttributes(definition.entityType, definition.attributes));
    dataModel.forEach((definition) => registerDefinition(definition));
  });
  descriptors.forEach(({ graphqlSchemas = [] }) => graphqlSchemas.forEach((graphqlSchema) => registerGraphqlSchema(graphqlSchema)));
  descriptors.forEach(({ managers = [] }) => managers.forEach((manager) => registerManager(manager)));
  descriptors.forEach(({ init }) => init?.());
};

import type { ModuleDescriptor } from './modules/module-descriptor';
import { registerDefinition } from './schema/module';
import { registerEntityOverviewLayoutCustomization } from './schema/overviewLayoutCustomization-register';
import { registerGraphqlSchema } from './graphql/schema';
import { registerManager } from './manager/managerModule';
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

// Each phase runs for every module before the next phase starts: data model (overview layouts, then
// definitions), graphql schemas, managers, then init. The whole of it runs after modules/index, so a migrated definition is
// registered after the graphql of the modules still registered on import, against the order
// modules/index documents. That is safe only while nothing reads the model at import time:
// usageProtection catches an early read of types, attributes or refs, not of converters or validators.
// Must run before anything reads the schema (selectEntityType, createSchema, startAllManagers).
export const registerModules = (descriptors: ModuleDescriptor[] = MODULE_DESCRIPTORS) => {
  if (modulesRegistered) {
    return;
  }
  modulesRegistered = true;
  descriptors.forEach(({ overviewLayouts = [], dataModel = [] }) => {
    overviewLayouts.forEach(({ entityType, layout }) => registerEntityOverviewLayoutCustomization(entityType, layout));
    dataModel.forEach((definition) => registerDefinition(definition));
  });
  descriptors.forEach(({ graphqlSchemas = [] }) => graphqlSchemas.forEach((graphqlSchema) => registerGraphqlSchema(graphqlSchema)));
  descriptors.forEach(({ managers = [] }) => managers.forEach((manager) => registerManager(manager)));
  descriptors.forEach(({ init }) => init?.());
};

// Imported first, as modules/index used to be: the evaluation order of the schema files depends on it.
import { registerBasicObjectAttributes } from './modules/attributes/basicObject-registrationAttributes';
import { registerStixObjectAttributes } from './modules/attributes/stixObject-registrationAttributes';
import { registerStixCoreObjectAttributes } from './modules/attributes/stixCoreObject-registrationAttributes';
import { registerStixDomainObjectAttributes } from './modules/attributes/stixDomainObject-registrationAttributes';
import { registerInternalObjectAttributes } from './modules/attributes/internalObject-registrationAttributes';
import { registerBasicRelationshipAttributes } from './modules/attributes/basicRelationship-registrationAttributes';
import { registerInternalRelationshipAttributes } from './modules/attributes/internalRelationship-registrationAttributes';
import { registerStixRelationshipAttributes } from './modules/attributes/stixRelationship-registrationAttributes';
import { registerStixCoreRelationshipAttributes } from './modules/attributes/stixCoreRelationship-registrationAttributes';
import { registerStixRefRelationshipAttributes } from './modules/attributes/stixRefRelationship-registrationAttributes';
import { registerStixSightingRelationshipAttributes } from './modules/attributes/stixSightingRelationship-registrationAttributes';
import { registerStixCyberObservableAttributes } from './modules/attributes/stixCyberObservable-registrationAttributes';
import { registerStixMetaObjectAttributes } from './modules/attributes/stixMetaObject-registrationAttributes';
import { registerStixCoreObjectRelationsRefs } from './modules/relationsRef/stixCoreObject-registrationRef';
import { registerStixDomainObjectRelationsRefs } from './modules/relationsRef/stixDomainObject-registrationRef';
import { registerStixRelationshipRelationsRefs } from './modules/relationsRef/stixRelationship-registrationRef';
import { registerInternalRelationshipRelationsRefs } from './modules/relationsRef/internalRelationship-registrationRef';
import { registerInternalObjectRelationsRefs } from './modules/relationsRef/internalObject-registrationRef';
import { registerStixMetaObjectRelationsRefs } from './modules/relationsRef/stixMetaObject-registrationRef';
import { registerStixCyberObservableRelationsRefs } from './modules/relationsRef/stixCyberObservable-registrationRef';
import type { ModuleDescriptor } from './modules/module-descriptor';
import { registerDefinition } from './schema/module';
import { registerEntityOverviewLayoutCustomization } from './schema/overviewLayoutCustomization-register';
import { schemaAttributesDefinition } from './schema/schema-attributes';
import { registerGraphqlSchema } from './graphql/schema';
import { registerManager } from './manager/managerModule';
import channelModule from './modules/channel/channel-module';
import catalogModule from './modules/catalog/catalog-module';
import connectorModule from './modules/connector/connector-module';
import ingestionHealthModule from './modules/ingestionHealth/ingestionHealth-module';
import languageModule from './modules/language/language-module';
import eventModule from './modules/event/event-module';
import groupingModule from './modules/grouping/grouping-module';
import narrativeModule from './modules/narrative/narrative-module';
import notificationModule from './modules/notification/notification-module';
import dataComponentModule from './modules/dataComponent/dataComponent-module';
import dataSourceModule from './modules/dataSource/dataSource-module';
import vocabularyModule from './modules/vocabulary/vocabulary-module';
import administrativeAreaModule from './modules/administrativeArea/administrativeArea-module';
import taskModule from './modules/task/task-module';
import taskTemplateModule from './modules/task/task-template/task-template-module';
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
import configPresetModule from './modules/configPreset/configPreset-module';

// Every module, in the registration order modules/index used to enforce.
// Still registered on import: the managers that belong to no module (manager/index).
export const MODULE_DESCRIPTORS: ModuleDescriptor[] = [
  channelModule,
  catalogModule,
  connectorModule,
  ingestionHealthModule,
  languageModule,
  eventModule,
  groupingModule,
  narrativeModule,
  notificationModule,
  dataComponentModule,
  dataSourceModule,
  vocabularyModule,
  administrativeAreaModule,
  taskModule,
  taskTemplateModule,
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
  configPresetModule,
];

let modulesRegistered = false;

// Attributes, then refs, of the abstract types, which every module definition inherits from.
const registerAbstractDataModel = () => {
  registerBasicObjectAttributes();
  registerStixObjectAttributes();
  registerStixCoreObjectAttributes();
  registerStixDomainObjectAttributes();
  registerInternalObjectAttributes();
  registerBasicRelationshipAttributes();
  registerInternalRelationshipAttributes();
  registerStixRelationshipAttributes();
  registerStixCoreRelationshipAttributes();
  registerStixRefRelationshipAttributes();
  registerStixSightingRelationshipAttributes();
  registerStixCyberObservableAttributes();
  registerStixMetaObjectAttributes();
  registerStixCoreObjectRelationsRefs();
  registerStixDomainObjectRelationsRefs();
  registerStixRelationshipRelationsRefs();
  registerInternalRelationshipRelationsRefs();
  registerInternalObjectRelationsRefs();
  registerStixMetaObjectRelationsRefs();
  registerStixCyberObservableRelationsRefs();
};

// The abstract data model comes first. Then each phase runs for every module before the next phase starts:
// data model (overview layouts, attributes, then definitions), graphql schemas, managers, then init.
// usageProtection catches a read of types, attributes or refs made earlier, not of converters or validators.
// Must run before anything reads the schema (selectEntityType, createSchema, startAllManagers).
export const registerModules = (descriptors: ModuleDescriptor[] = MODULE_DESCRIPTORS) => {
  if (modulesRegistered) {
    return;
  }
  modulesRegistered = true;
  registerAbstractDataModel();
  descriptors.forEach(({ overviewLayouts = [], attributes = [], dataModel = [] }) => {
    overviewLayouts.forEach(({ entityType, layout }) => registerEntityOverviewLayoutCustomization(entityType, layout));
    attributes.forEach((definition) => schemaAttributesDefinition.registerAttributes(definition.entityType, definition.attributes));
    dataModel.forEach((definition) => registerDefinition(definition));
  });
  descriptors.forEach(({ graphqlSchemas = [] }) => graphqlSchemas.forEach((graphqlSchema) => registerGraphqlSchema(graphqlSchema)));
  descriptors.forEach(({ managers = [] }) => managers.forEach((manager) => registerManager(manager)));
  descriptors.forEach(({ init }) => init?.());
};

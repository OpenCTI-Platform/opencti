/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/
import * as R from 'ramda';
import { v4 as uuidv4 } from 'uuid';
import type { JSONSchemaType } from 'ajv';
import * as jsonpatch from 'fast-json-patch';
import { type BasicStoreEntityPlaybook, ENTITY_TYPE_PLAYBOOK, type PlaybookComponent } from './playbook-types';
import { AUTOMATION_MANAGER_USER, AUTOMATION_MANAGER_USER_UUID, executionContext, isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { pushToConnector, pushToWorkerForConnector } from '../../database/rabbitmq';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_THREAT_ACTOR,
  INPUT_ASSIGNEE,
  INPUT_CREATED_BY,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_PARTICIPANT,
  OPENCTI_ADMIN_UUID,
} from '../../schema/general';
import type { BasicStoreCommon, BasicStoreRelation, StoreCommon, StoreRelation } from '../../types/store';
import { generateInternalId, generateStandardId, idGenFromData } from '../../schema/identifier';
import { now, observableValue, utcDate } from '../../utils/format';
import type { StixCampaign, StixContainer, StixIncident, StixInfrastructure, StixMalware, StixReport, StixThreatActor } from '../../types/stix-2-1-sdo';
import { convertStixToInternalTypes, generateInternalType, getParentTypes } from '../../schema/schemaUtils';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  isStixDomainObjectContainer,
  STIX_DOMAIN_OBJECT_CONTAINER_CASES,
} from '../../schema/stixDomainObject';
import type { CyberObjectExtension, StixBundle, StixCoreObject, StixCyberObject, StixDomainObject, StixObject, StixOpenctiExtension } from '../../types/stix-2-1-common';
import { STIX_EXT_MITRE, STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../types/stix-2-1-extensions';
import { connectorsForPlaybook } from '../../database/repository';
import { internalFindByIds, fullEntitiesList, fullRelationsList, storeLoadById } from '../../database/middleware-loader';
import { type BasicStoreEntityOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../database/cache';
import { createdBy, objectLabel, objectMarking } from '../../schema/stixRefRelationship';
import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { extractStixRepresentative } from '../../database/stix-representative';
import { isEmptyField, isNotEmptyField, READ_RELATIONSHIPS_INDICES, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { stixLoadByIds } from '../../database/middleware';
import { usableNotifiers } from '../notifier/notifier-domain';
import { convertToNotificationUser, type DigestEvent, EVENT_NOTIFICATION_VERSION } from '../../manager/notificationManager';
import { storeNotificationEvent } from '../../database/stream/stream-handler';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { createStixPattern } from '../../python/pythonBridge';
import { generateKeyValueForIndicator } from '../../domain/stixCyberObservable';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import type { StixRelation } from '../../types/stix-2-1-sro';
import { extractValidObservablesFromIndicatorPattern, STIX_PATTERN_TYPE } from '../../utils/syntax';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT, type StixCaseIncident } from '../case/case-incident/case-incident-types';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { ENTITY_TYPE_INDICATOR, type StixIndicator } from '../indicator/indicator-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../case/case-rft/case-rft-types';
import { ENTITY_TYPE_CONTAINER_TASK, type StixTask, type StoreEntityTask } from '../task/task-types';
import { EditOperation, FilterMode } from '../../generated/graphql';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { generateCreateMessage } from '../../database/generate-message';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { findAllByCaseTemplateId } from '../task/task-domain';
import type { BasicStoreEntityTaskTemplate } from '../task/task-template/task-template-types';
import type { BasicStoreSettings } from '../../types/settings';
import { AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES, editAuthorizedMembers } from '../../utils/authorizedMembers';
import { removeOrganizationRestriction } from '../../domain/stix';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../case/feedback/feedback-types';
import { PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT } from './components/send-email-template-component';
import { PLAYBOOK_DATA_STREAM_PIR } from './components/data-stream-pir-component';
import { convertMembersToUsers, extractBundleBaseElement } from './playbook-utils';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { ENTITY_TYPE_SECURITY_COVERAGE, INPUT_COVERED, type StixSecurityCoverage, type StoreEntitySecurityCoverage } from '../securityCoverage/securityCoverage-types';

// region built in playbook components
interface LoggerConfiguration {
  level: string;
}
const PLAYBOOK_LOGGER_COMPONENT_SCHEMA: JSONSchemaType<LoggerConfiguration> = {
  type: 'object',
  properties: {
    level: {
      type: 'string',
      default: 'debug',
      $ref: 'Log level',
      oneOf: [
        { const: 'debug', title: 'debug' },
        { const: 'info', title: 'info' },
        { const: 'warn', title: 'warn' },
        { const: 'error', title: 'error' },
      ],
    },
  },
  required: ['level'],
};
const PLAYBOOK_LOGGER_COMPONENT: PlaybookComponent<LoggerConfiguration> = {
  id: 'PLAYBOOK_LOGGER_COMPONENT',
  name: 'Log data in standard output',
  description: 'Print bundle in platform logs',
  icon: 'console',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_LOGGER_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_LOGGER_COMPONENT_SCHEMA,
  executor: async ({ bundle, playbookNode }) => {
    if (playbookNode.configuration.level) {
      logApp._log(playbookNode.configuration.level, '[PLAYBOOK MANAGER] Logger component output', { bundle });
    }
    return { output_port: 'out', bundle, forceBundleTracking: true };
  },
};

export interface StreamConfiguration {
  create: boolean;
  update: boolean;
  delete: boolean;
  filters: string;
}
const PLAYBOOK_INTERNAL_DATA_STREAM_SCHEMA: JSONSchemaType<StreamConfiguration> = {
  type: 'object',
  properties: {
    create: { type: 'boolean', default: true },
    update: { type: 'boolean', default: false },
    delete: { type: 'boolean', default: false },
    filters: { type: 'string' },
  },
  required: ['create', 'update', 'delete'],
};
const PLAYBOOK_INTERNAL_DATA_STREAM: PlaybookComponent<StreamConfiguration> = {
  id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
  name: 'Listen knowledge events',
  description: 'Listen for all platform knowledge events',
  icon: 'stream',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_INTERNAL_DATA_STREAM_SCHEMA,
  schema: async () => PLAYBOOK_INTERNAL_DATA_STREAM_SCHEMA,
  executor: async ({ bundle }) => {
    return ({ output_port: 'out', bundle, forceBundleTracking: true });
  },
};

export interface ManualTriggerConfiguration {
  filters: string;
}
const PLAYBOOK_INTERNAL_MANUAL_TRIGGER_SCHEMA: JSONSchemaType<ManualTriggerConfiguration> = {
  type: 'object',
  properties: {
    filters: { type: 'string' },
  },
  required: [],
};
const PLAYBOOK_INTERNAL_MANUAL_TRIGGER: PlaybookComponent<ManualTriggerConfiguration> = {
  id: 'PLAYBOOK_INTERNAL_MANUAL_TRIGGER',
  name: 'Available for manual enrollment / trigger',
  description: 'To be used in manual enrollment / trigger',
  icon: 'manual',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_INTERNAL_MANUAL_TRIGGER_SCHEMA,
  schema: async () => PLAYBOOK_INTERNAL_MANUAL_TRIGGER_SCHEMA,
  executor: async ({ bundle }) => {
    return ({ output_port: 'out', bundle, forceBundleTracking: true });
  },
};

export interface CronConfiguration {
  period: 'day' | 'hour' | 'minute' | 'month' | 'week';
  triggerTime: string;
  onlyLast: boolean;
  includeAll: boolean;
  filters: string;
}
const PLAYBOOK_INTERNAL_DATA_CRON_SCHEMA: JSONSchemaType<CronConfiguration> = {
  type: 'object',
  properties: {
    period: { type: 'string', default: 'hour' },
    triggerTime: { type: 'string' },
    onlyLast: { type: 'boolean', $ref: 'Only last modified entities after the last run', default: false },
    includeAll: { type: 'boolean', $ref: 'Include all entities in a single bundle', default: false },
    filters: { type: 'string' },
  },
  required: ['period', 'triggerTime', 'onlyLast', 'filters'],
};
export const PLAYBOOK_INTERNAL_DATA_CRON: PlaybookComponent<CronConfiguration> = {
  id: 'PLAYBOOK_INTERNAL_DATA_CRON',
  name: 'Query knowledge on a regular basis',
  description: 'Query knowledge on the platform',
  icon: 'cron',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_INTERNAL_DATA_CRON_SCHEMA,
  schema: async () => PLAYBOOK_INTERNAL_DATA_CRON_SCHEMA,
  executor: async ({ bundle }) => {
    return ({ output_port: 'out', bundle, forceBundleTracking: true });
  },
};

// eslint-disable-next-line  @typescript-eslint/no-empty-object-type
interface IngestionConfiguration {}
const PLAYBOOK_INGESTION_COMPONENT: PlaybookComponent<IngestionConfiguration> = {
  id: 'PLAYBOOK_INGESTION_COMPONENT',
  name: 'Send for ingestion',
  description: 'Send STIX data for ingestion',
  icon: 'storage',
  is_entry_point: false,
  is_internal: true,
  ports: [],
  configuration_schema: undefined,
  schema: async () => undefined,
  executor: async ({ eventId, bundle, playbookId }) => {
    const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
    await pushToWorkerForConnector(playbookId, {
      type: 'bundle',
      event_id: eventId,
      playbook_id: playbookId,
      applicant_id: AUTOMATION_MANAGER_USER_UUID,
      content,
      update: false,
    });
    return { output_port: undefined, bundle, forceBundleTracking: true };
  },
};

interface MatchConfiguration {
  all: boolean;
  filters: string;
}
const PLAYBOOK_MATCHING_COMPONENT_SCHEMA: JSONSchemaType<MatchConfiguration> = {
  type: 'object',
  properties: {
    all: { type: 'boolean', $ref: 'Match on any elements included in the bundle', default: false },
    filters: { type: 'string' },
  },
  required: ['filters'],
};
export const PLAYBOOK_MATCHING_COMPONENT: PlaybookComponent<MatchConfiguration> = {
  id: 'PLAYBOOK_FILTERING_COMPONENT',
  name: 'Match knowledge',
  description: 'Match STIX data according to filter (pass if match)',
  icon: 'filter',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'no-match', type: 'out' }],
  configuration_schema: PLAYBOOK_MATCHING_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_MATCHING_COMPONENT_SCHEMA,
  executor: async ({ playbookNode, dataInstanceId, bundle }) => {
    const context = executionContext('playbook_components');
    const { filters, all } = playbookNode.configuration;
    const jsonFilters = JSON.parse(filters);
    // Checking on all bundle elements
    if (all) {
      let matchedElements = 0;
      for (let index = 0; index < bundle.objects.length; index += 1) {
        const bundleElement = bundle.objects[index];
        const isMatch = await isStixMatchFilterGroup(context, SYSTEM_USER, bundleElement, jsonFilters);
        if (isMatch) matchedElements += 1;
      }
      return { output_port: matchedElements > 0 ? 'out' : 'no-match', bundle };
    }
    // Only checking base data
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const isMatch = await isStixMatchFilterGroup(context, SYSTEM_USER, baseData, jsonFilters);
    return { output_port: isMatch ? 'out' : 'no-match', bundle };
  },
};

interface ReduceConfiguration {
  filters: string;
}
const PLAYBOOK_REDUCING_COMPONENT_SCHEMA: JSONSchemaType<ReduceConfiguration> = {
  type: 'object',
  properties: {
    filters: { type: 'string' },
  },
  required: ['filters'],
};
const PLAYBOOK_REDUCING_COMPONENT: PlaybookComponent<ReduceConfiguration> = {
  id: 'PLAYBOOK_REDUCING_COMPONENT',
  name: 'Reduce knowledge',
  description: 'Reduce STIX data according to the filter (keep only matching)',
  icon: 'reduce',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmatch', type: 'out' }],
  configuration_schema: PLAYBOOK_REDUCING_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_REDUCING_COMPONENT_SCHEMA,
  executor: async ({ playbookNode, dataInstanceId, bundle }) => {
    const context = executionContext('playbook_components');
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const { filters } = playbookNode.configuration;
    const jsonFilters = JSON.parse(filters);
    const baseMatches = await isStixMatchFilterGroup(context, SYSTEM_USER, baseData, jsonFilters);
    if (!baseMatches) {
      return { output_port: 'unmatch', bundle };
    }
    const matchedElements = [baseData];
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const bundleElement = bundle.objects[index];
      const isMatch = await isStixMatchFilterGroup(context, SYSTEM_USER, bundleElement, jsonFilters);
      if (isMatch && baseData.id !== bundleElement.id) matchedElements.push(bundleElement);
    }
    const newBundle = { ...bundle, objects: matchedElements };
    return { output_port: 'out', bundle: newBundle };
  },
};

interface ConnectorConfiguration {
  connector: string;
}
const PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA: JSONSchemaType<ConnectorConfiguration> = {
  type: 'object',
  properties: {
    connector: { type: 'string', $ref: 'Enrichment connector', oneOf: [] },
  },
  required: ['connector'],
};
const extendsBundleElementsWithExtensions = (bundle: StixBundle): StixBundle => {
  const newBundle = structuredClone(bundle);
  newBundle.objects = newBundle.objects.map((element) => {
    const data = structuredClone(element);
    const openctiType = generateInternalType(data); // convert from stix type
    // eslint-disable-next-line
    // @ts-ignore
    data.extensions = isEmptyField(element.extensions) ? {} : element.extensions;
    if (isEmptyField(data.extensions[STIX_EXT_OCTI])) {
      data.extensions[STIX_EXT_OCTI] = { extension_type: 'property-extension', type: openctiType } as StixOpenctiExtension;
    }
    if (isStixCyberObservable(openctiType)) {
      const cyberObject = data as StixCyberObject;
      if (isEmptyField(cyberObject.extensions[STIX_EXT_OCTI_SCO])) {
        cyberObject.extensions[STIX_EXT_OCTI_SCO] = { extension_type: 'property-extension' } as CyberObjectExtension;
      }
    }
    return data;
  });
  return newBundle;
};
const PLAYBOOK_CONNECTOR_COMPONENT: PlaybookComponent<ConnectorConfiguration> = {
  id: 'PLAYBOOK_CONNECTOR_COMPONENT',
  name: 'Enrich through connector',
  description: 'Use a registered platform connector for enrichment',
  icon: 'connector',
  is_entry_point: false,
  is_internal: false,
  ports: [{ id: 'out', type: 'out' }], // { id: 'unmodified', type: 'out' }]
  configuration_schema: PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const connectors = await connectorsForPlaybook(context, SYSTEM_USER);
    const elements = connectors.map((c) => ({ const: c.id, title: c.name }))
      .sort((a, b) => (a.title.toLowerCase() > b.title.toLowerCase() ? 1 : -1));
    const schemaElement = { properties: { connector: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<ConnectorConfiguration>, any>(PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA, schemaElement);
  },
  notify: async ({ executionId, eventId, playbookId, playbookNode,
    previousPlaybookNodeId, dataInstanceId, bundle }) => {
    if (playbookNode.configuration.connector) {
      const baseData = extractBundleBaseElement(dataInstanceId, bundle);
      const message = {
        internal: {
          work_id: null, // No work id associated
          playbook: {
            event_id: eventId,
            execution_id: executionId,
            playbook_id: playbookId,
            data_instance_id: dataInstanceId,
            step_id: playbookNode.id,
            previous_step_id: previousPlaybookNodeId,
          },
          applicant_id: AUTOMATION_MANAGER_USER.id, // System user is responsible for the automation
          trigger: isNotEmptyField(baseData.extensions?.[STIX_EXT_OCTI]?.id) ? 'create' : 'update',
          mode: 'auto',
        },
        event: {
          entity_id: dataInstanceId,
          bundle,
        },
      };
      await pushToConnector(playbookNode.configuration.connector, message);
    }
  },
  executor: async ({ bundle }) => {
    // Add extensions if needed
    // This is needed as the rest of playbook expecting STIX2.1 format with extensions
    const stixBundle = extendsBundleElementsWithExtensions(bundle);
    // TODO Could be reactivated after improvement of enrichment connectors
    // if (previousStepBundle) {
    //   const diffOperations = jsonpatch.compare(previousStepBundle.objects, bundle.objects);
    //   if (diffOperations.length === 0) {
    //     return { output_port: 'unmodified', bundle };
    //   }
    // }
    return { output_port: 'out', bundle: stixBundle };
  },
};

interface ContainerWrapperConfiguration {
  container_type: string;
  caseTemplates: { label: string; value: string }[];
  all: boolean;
  newContainer: boolean;
}
const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA: JSONSchemaType<ContainerWrapperConfiguration> = {
  type: 'object',
  properties: {
    container_type: { type: 'string', $ref: 'Container type', default: '', oneOf: [] },
    caseTemplates: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Case templates',
      items: { type: 'string', oneOf: [] },
    },
    all: { type: 'boolean', $ref: 'Wrap all elements included in the bundle', default: false },
    newContainer: { type: 'boolean', $ref: 'Create a new container at each run', default: false },
  },
  required: ['container_type'],
};

// For now, only a fixed list of containers are compatible
// these are the containers that can be created with a name and no specific mandatory fields
const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_AVAILABLE_CONTAINERS = [
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
  ENTITY_TYPE_CONTAINER_CASE_RFI,
  ENTITY_TYPE_CONTAINER_CASE_RFT,
  ENTITY_TYPE_CONTAINER_FEEDBACK,
  ENTITY_TYPE_CONTAINER_TASK,
];

export const buildStixTaskFromTaskTemplate = (taskTemplate: BasicStoreEntityTaskTemplate, container: StixContainer) => {
  const taskData = {
    name: taskTemplate.name,
    description: taskTemplate.description,
  };
  const taskStandardId = generateStandardId(ENTITY_TYPE_CONTAINER_TASK, taskData);
  const storeTask = {
    internal_id: generateInternalId(),
    standard_id: taskStandardId,
    entity_type: ENTITY_TYPE_CONTAINER_TASK,
    parent_types: getParentTypes(ENTITY_TYPE_CONTAINER_TASK),
    ...taskData,
  } as StoreEntityTask;
  const task = convertStoreToStix_2_1(storeTask) as StixTask;
  task.object_refs = [container.id];
  task.object_marking_refs = container.object_marking_refs;
  return task;
};

export const addTaskFromCaseTemplates = async (
  caseTemplates: { label: string; value: string }[],
  container: StixContainer,
) => {
  const context = executionContext('playbook_components');
  const tasks = [];
  for (let i = 0; i < caseTemplates.length; i += 1) {
    const taskTemplates = await findAllByCaseTemplateId(context, AUTOMATION_MANAGER_USER, caseTemplates[i].value);
    for (let j = 0; j < taskTemplates.length; j += 1) {
      const task = buildStixTaskFromTaskTemplate(taskTemplates[j], container);
      tasks.push(task);
    }
  }
  return tasks;
};

export const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT: PlaybookComponent<ContainerWrapperConfiguration> = {
  id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
  name: 'Container wrapper',
  description: 'Create a container and wrap the element inside it',
  icon: 'container',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA,
  schema: async () => {
    const elements = PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_AVAILABLE_CONTAINERS.map((t) => ({ const: t, title: t }));
    const schemaElement = { properties: { container_type: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<ContainerWrapperConfiguration>, any>(PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const { container_type, all, newContainer, caseTemplates } = playbookNode.configuration;
    if (!PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_AVAILABLE_CONTAINERS.includes(container_type)) {
      throw FunctionalError('this container type is incompatible with the Container Wrapper playbook component', { container_type });
    }
    if (container_type) {
      const baseData = extractBundleBaseElement(dataInstanceId, bundle);
      const created = newContainer ? now() : baseData.extensions[STIX_EXT_OCTI].created_at;
      const representative = extractStixRepresentative(baseData);
      let name = `Generated container wrapper from playbook at ${created}`;
      if (representative && newContainer) {
        name = `${representative} - ${created}`;
      } else if (representative) {
        name = representative;
      }
      const containerData: Record<string, unknown> = {
        name,
        created,
      };
      if (container_type === ENTITY_TYPE_CONTAINER_REPORT) {
        containerData.published = created;
      }
      if (container_type === ENTITY_TYPE_CONTAINER_GROUPING) {
        containerData.context = 'playbook';
      }
      const standardId = generateStandardId(container_type, containerData);
      const storeContainer = {
        internal_id: uuidv4(),
        standard_id: standardId,
        entity_type: container_type,
        parent_types: getParentTypes(container_type),
        ...containerData,
      } as StoreCommon;
      const container = convertStoreToStix_2_1(storeContainer) as StixReport | StixCaseIncident;
      // add all objects in the container if requested in the playbook config
      if (all) {
        container.object_refs = bundle.objects.map((o: StixObject) => o.id);
      } else {
        container.object_refs = [baseData.id];
      }
      // Specific remapping of some attributes, waiting for a complete binding solution in the UI
      // Following attributes are the same as the base instance: description, content, markings, labels, created_by, assignees, participants
      if ((baseData as StixReport).description) {
        container.description = (baseData as StixReport).description;
      }
      if ((baseData as StixReport).extensions[STIX_EXT_OCTI].content) {
        (container as StixReport).extensions[STIX_EXT_OCTI].content = (baseData as StixReport).extensions[STIX_EXT_OCTI].content;
      }
      if ((baseData as StixCaseIncident).content) {
        (container as StixCaseIncident).content = (baseData as StixCaseIncident).content;
      }
      if (baseData.object_marking_refs) {
        container.object_marking_refs = baseData.object_marking_refs;
      }
      if ((<StixDomainObject>baseData).labels) {
        container.labels = (<StixDomainObject>baseData).labels;
      }
      if ((<StixDomainObject>baseData).created_by_ref) {
        container.created_by_ref = (<StixDomainObject>baseData).created_by_ref;
      }
      if (baseData.extensions[STIX_EXT_OCTI].participant_ids) {
        container.extensions[STIX_EXT_OCTI].participant_ids = baseData.extensions[STIX_EXT_OCTI].participant_ids;
      }
      if (baseData.extensions[STIX_EXT_OCTI].assignee_ids) {
        container.extensions[STIX_EXT_OCTI].assignee_ids = baseData.extensions[STIX_EXT_OCTI].assignee_ids;
      }
      // if the base instance is an incident and we wrap into an Incident Case, we set the same severity
      if ((<StixIncident>baseData).severity && container_type === ENTITY_TYPE_CONTAINER_CASE_INCIDENT) {
        (<StixCaseIncident>container).severity = (<StixIncident>baseData).severity;
      }
      if (STIX_DOMAIN_OBJECT_CONTAINER_CASES.includes(container_type) && caseTemplates.length > 0) {
        const tasks = await addTaskFromCaseTemplates(caseTemplates, (container as StixContainer));
        bundle.objects.push(...tasks);
      }
      bundle.objects.push(container);
    }
    return { output_port: 'out', bundle };
  },
};

interface SecurityCoverageConfiguration {
  all: boolean;
  auto_enrichment_disable: boolean;
  periodicity: string;
  duration: string;
  type_affinity: string;
  platforms_affinity: string[];
}
const PLAYBOOK_SECURITY_COVERAGE_COMPONENT_SCHEMA: JSONSchemaType<SecurityCoverageConfiguration> = {
  type: 'object',
  properties: {
    all: { type: 'boolean', $ref: 'Create a security coverage for each element of the bundle (on compatible types)', default: false },
    auto_enrichment_disable: { type: 'boolean', $ref: 'Force manual coverage (prevent enrichment connectors from running)', default: false },
    periodicity: { type: 'string', $ref: 'Coverage recurrence (every x)', default: 'P1D' },
    duration: { type: 'string', $ref: 'Duration', default: 'P30D' },
    type_affinity: {
      type: 'string',
      $ref: 'Type affinity',
      default: 'ENDPOINT',
    },
    platforms_affinity: {
      type: 'array',
      uniqueItems: true,
      default: ['windows', 'linux', 'macos'],
      $ref: 'Platform(s) affinity',
      items: { type: 'string', oneOf: [] },
    },
  },
  required: ['periodicity', 'duration', 'type_affinity', 'platforms_affinity'],
};

const SECURITY_COVERAGE_COMPATIBLE_TYPES = [
  'report',
  'grouping',
  'case-incident',
  'x-opencti-case-incident',
  'intrusion-set',
  'campaign',
  'incident',
];

export const PLAYBOOK_SECURITY_COVERAGE_COMPONENT: PlaybookComponent<SecurityCoverageConfiguration> = {
  id: 'PLAYBOOK_SECURITY_COVERAGE_COMPONENT',
  name: 'Security coverage',
  description: 'Create a security coverage for the given entity(ies) (when type is compatible)',
  icon: 'security-coverage',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_SECURITY_COVERAGE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_SECURITY_COVERAGE_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const { all, auto_enrichment_disable, periodicity, duration, type_affinity, platforms_affinity } = playbookNode.configuration;
    const baseData = extractBundleBaseElement(dataInstanceId, bundle) as StixDomainObject;
    if (SECURITY_COVERAGE_COMPATIBLE_TYPES.includes(baseData.type)) {
      const name = extractStixRepresentative(baseData);
      const securityCoverageData: Record<string, unknown> = {
        name,
        created: now(),
        auto_enrichment_disable: auto_enrichment_disable,
        periodicity: periodicity,
        duration: duration,
        type_affinity: type_affinity,
        platforms_affinity: platforms_affinity,
        [INPUT_COVERED]: { standard_id: baseData.id },
        [INPUT_LABELS]: (baseData.labels ?? []).map((l) => ({ value: l })),
      };
      const standardId = generateStandardId(ENTITY_TYPE_SECURITY_COVERAGE, securityCoverageData);
      const storeSecurityCoverage = {
        internal_id: uuidv4(),
        standard_id: standardId,
        entity_type: ENTITY_TYPE_SECURITY_COVERAGE,
        parent_types: getParentTypes(ENTITY_TYPE_SECURITY_COVERAGE),
        ...securityCoverageData,
      } as StoreEntitySecurityCoverage;
      const securityCoverage = convertStoreToStix_2_1(storeSecurityCoverage) as StixSecurityCoverage;
      bundle.objects.push(securityCoverage);
    }
    if (all) {
      for (let index = 0; index < bundle.objects.length; index += 1) {
        const element = bundle.objects[index] as StixDomainObject;
        if (SECURITY_COVERAGE_COMPATIBLE_TYPES.includes(element.type)) {
          const name = extractStixRepresentative(element);
          const securityCoverageData: Record<string, unknown> = {
            name,
            created: now(),
            auto_enrichment_disable: auto_enrichment_disable,
            periodicity: periodicity,
            duration: duration,
            type_affinity: type_affinity,
            [INPUT_COVERED]: { standard_id: element.id },
            [INPUT_LABELS]: (element.labels ?? []).map((l) => ({ value: l })),
          };
          const standardId = generateStandardId(ENTITY_TYPE_SECURITY_COVERAGE, securityCoverageData);
          const storeContainer = {
            internal_id: uuidv4(),
            standard_id: standardId,
            entity_type: ENTITY_TYPE_SECURITY_COVERAGE,
            parent_types: getParentTypes(ENTITY_TYPE_SECURITY_COVERAGE),
            ...securityCoverageData,
          } as StoreCommon;
          const securityCoverage = convertStoreToStix_2_1(storeContainer) as StixSecurityCoverage;
          bundle.objects.push(securityCoverage);
        }
      }
    }
    return { output_port: 'out', bundle };
  },
};

export interface SharingConfiguration {
  organizations: string[] | { label: string; value: string }[];
  all: boolean;
}
const PLAYBOOK_SHARING_COMPONENT_SCHEMA: JSONSchemaType<SharingConfiguration> = {
  type: 'object',
  properties: {
    organizations: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Target organizations',
      items: { type: 'string', oneOf: [] },
    },
    all: { type: 'boolean', $ref: 'Share all elements included in the bundle', default: false },
  },
  required: ['organizations'],
};
export const PLAYBOOK_SHARING_COMPONENT: PlaybookComponent<SharingConfiguration> = {
  id: 'PLAYBOOK_SHARING_COMPONENT',
  name: 'Share with organizations',
  description: 'Share with organizations within the platform',
  icon: 'organization-add',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_SHARING_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_SHARING_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const { organizations, all } = playbookNode.configuration;
    const organizationsValues = organizations.map((o) => (typeof o !== 'string' ? o.value : o));
    const organizationsByIds = await internalFindByIds<BasicStoreEntityOrganization>(context, SYSTEM_USER, organizationsValues, {
      type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
      baseData: true,
      baseFields: ['standard_id'],
    }) as BasicStoreEntityOrganization[];
    if (organizationsByIds.length === 0) {
      return { output_port: 'out', bundle }; // nothing to do since organizations are empty
    }
    const organizationIds = organizationsByIds.map((o) => o.standard_id);
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      if (all || element.id === dataInstanceId) {
        element.extensions[STIX_EXT_OCTI].granted_refs = [...(element.extensions[STIX_EXT_OCTI].granted_refs ?? []), ...organizationIds];
      }
    }
    return { output_port: 'out', bundle };
  },
};

export interface UnsharingConfiguration {
  organizations: string[] | { label: string; value: string }[];
  all: boolean;
}
const PLAYBOOK_UNSHARING_COMPONENT_SCHEMA: JSONSchemaType<UnsharingConfiguration> = {
  type: 'object',
  properties: {
    organizations: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Target organizations',
      items: { type: 'string', oneOf: [] },
    },
    all: { type: 'boolean', $ref: 'Unshare all elements included in the bundle', default: false },
  },
  required: ['organizations'],
};
export const PLAYBOOK_UNSHARING_COMPONENT: PlaybookComponent<UnsharingConfiguration> = {
  id: 'PLAYBOOK_UNSHARING_COMPONENT',
  name: 'Unshare with organizations',
  description: 'Unshare with organizations within the platform',
  icon: 'organization-remove',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_UNSHARING_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_UNSHARING_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components', AUTOMATION_MANAGER_USER);
    const { organizations, all } = playbookNode.configuration;
    const organizationsValues = organizations.map((o) => (typeof o !== 'string' ? o.value : o));
    const organizationsByIds = await internalFindByIds<BasicStoreEntityOrganization>(context, SYSTEM_USER, organizationsValues, {
      type: ENTITY_TYPE_IDENTITY_ORGANIZATION,
      baseData: true,
      baseFields: ['standard_id'],
    }) as BasicStoreEntityOrganization[];
    if (organizationsByIds.length === 0) {
      return { output_port: 'out', bundle }; // nothing to do since organizations are empty
    }
    const organizationIds = organizationsByIds.map((o) => o.standard_id);
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      if (all || element.id === dataInstanceId) {
        for (let index2 = 0; index2 < organizationsValues.length; index2 += 1) {
          await removeOrganizationRestriction(context, AUTOMATION_MANAGER_USER, element.extensions[STIX_EXT_OCTI].id, organizationsValues[index2]);
        }
        element.extensions[STIX_EXT_OCTI].granted_refs = (element.extensions[STIX_EXT_OCTI].granted_refs ?? []).filter((o) => !organizationIds.includes(o));
      }
    }
    return { output_port: 'out', bundle };
  },
};

export interface AccessRestrictionsConfiguration {
  access_restrictions: { groupsRestriction: { label: string; value: string; type: string }[]; accessRight: string; label: string; type: string; value: string }[];
  all: boolean;
}
const PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA: JSONSchemaType<AccessRestrictionsConfiguration> = {
  type: 'object',
  properties: {
    access_restrictions: {
      type: 'array',
      uniqueItems: true,
      default: [{
        label: 'Administrator',
        type: 'User',
        value: OPENCTI_ADMIN_UUID,
        accessRight: 'admin',
        groupsRestriction: [],
      }],
      $ref: 'Access restrictions',
      items: { type: 'object', oneOf: [] },
    },
    all: { type: 'boolean', $ref: 'Apply access restrictions on all elements included in the bundle', default: false },
  },
  required: ['access_restrictions'],
};
export const PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT: PlaybookComponent<AccessRestrictionsConfiguration> = {
  id: 'PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT',
  name: 'Manage access restrictions',
  description: 'Manage advanced access restrictions on entities',
  icon: 'lock',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const { access_restrictions: accessRestrictions, all } = playbookNode.configuration;
    // Resolve potential dynamic access rights
    const baseData = extractBundleBaseElement(dataInstanceId, bundle) as StixObject;
    const finalAccessRestrictions = [];
    for (let index = 0; index < accessRestrictions.length; index += 1) {
      const accessRestriction = accessRestrictions[index];
      if (accessRestriction.value === 'AUTHOR') {
        // If dynamic binding of author and an author is really defined in the data
        const createdById = baseData.extensions[STIX_EXT_OCTI].created_by_ref_id;
        const createdByType = baseData.extensions[STIX_EXT_OCTI].created_by_ref_type;
        if (isNotEmptyField(createdById) && createdByType === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
          finalAccessRestrictions.push({ ...accessRestriction, value: createdById });
        }
      } else if (accessRestriction.value === 'CREATORS') {
        const creators = (baseData.extensions[STIX_EXT_OCTI].creator_ids ?? []).filter((id) => isNotEmptyField(id));
        for (let index2 = 0; index2 < creators.length; index2 += 1) {
          finalAccessRestrictions.push({ ...accessRestriction, value: creators[index2] });
        }
      } else if (accessRestriction.value === 'ASSIGNEES') {
        const assignees = (baseData.extensions[STIX_EXT_OCTI].assignee_ids ?? []).filter((id) => isNotEmptyField(id));
        for (let index2 = 0; index2 < assignees.length; index2 += 1) {
          finalAccessRestrictions.push({ ...accessRestriction, value: assignees[index2] });
        }
      } else if (accessRestriction.value === 'PARTICIPANTS') {
        const participants = (baseData.extensions[STIX_EXT_OCTI].participant_ids ?? []).filter((id) => isNotEmptyField(id));
        for (let index2 = 0; index2 < participants.length; index2 += 1) {
          finalAccessRestrictions.push({ ...accessRestriction, value: participants[index2] });
        }
      } else if (accessRestriction.value === 'BUNDLE_ORGANIZATIONS') {
        const bundleOrganizations = bundle.objects.filter((o) => o.extensions[STIX_EXT_OCTI].type === ENTITY_TYPE_IDENTITY_ORGANIZATION);
        const bundleOrganizationsIds = bundleOrganizations.map((o) => o.extensions[STIX_EXT_OCTI].id).filter((id) => isNotEmptyField(id));
        for (let index2 = 0; index2 < bundleOrganizationsIds.length; index2 += 1) {
          finalAccessRestrictions.push({ ...accessRestriction, value: bundleOrganizationsIds[index2] });
        }
      } else {
        finalAccessRestrictions.push(accessRestriction);
      }
    }
    const input = finalAccessRestrictions.map((n) => ({
      id: n.value,
      access_right: n.accessRight,
      groups_restriction_ids: n.groupsRestriction.map((o) => o.value),
    }));
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      const internalType = generateInternalType(element);
      if (AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES.includes(internalType) && (all || element.id === dataInstanceId)) {
        const args = {
          entityId: element.id,
          input,
          requiredCapabilities: ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS'],
          entityType: internalType,
          busTopicKey: ABSTRACT_STIX_DOMAIN_OBJECT,
        };
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        await editAuthorizedMembers(context, AUTOMATION_MANAGER_USER, args);
      }
    }
    return { output_port: 'out', bundle };
  },
};
export interface RemoveAccessRestrictionsConfiguration {
  all: boolean;
}
const PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA: JSONSchemaType<RemoveAccessRestrictionsConfiguration> = {
  type: 'object',
  properties: {
    all: { type: 'boolean', $ref: 'Remove access restrictions on all elements included in the bundle', default: false },
  },
  required: [],
};
export const PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT: PlaybookComponent<RemoveAccessRestrictionsConfiguration> = {
  id: 'PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT',
  name: 'Remove access restrictions',
  description: 'Remove advanced access restrictions on entities',
  icon: 'lock-remove',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const { all } = playbookNode.configuration;
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      const internalType = generateInternalType(element);
      if (AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES.includes(internalType) && (all || element.id === dataInstanceId)) {
        const args = {
          entityId: element.id,
          input: null,
          requiredCapabilities: ['KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS'],
          entityType: internalType,
          busTopicKey: ABSTRACT_STIX_DOMAIN_OBJECT,
        };
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        await editAuthorizedMembers(context, AUTOMATION_MANAGER_USER, args);
      }
    }
    return { output_port: 'out', bundle };
  },
};

const attributePathMapping: any = {
  [INPUT_MARKINGS]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/${objectMarking.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${objectMarking.stixName}`,
  },
  [INPUT_LABELS]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/${objectLabel.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${objectLabel.stixName}`,
  },
  [INPUT_CREATED_BY]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/${createdBy.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${createdBy.stixName}`,
  },
  [INPUT_ASSIGNEE]: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/extensions/${STIX_EXT_OCTI}/assignee_ids`,
  },
  [INPUT_PARTICIPANT]: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/extensions/${STIX_EXT_OCTI}/participant_ids`,
  },
  confidence: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: '/confidence',
    [ABSTRACT_STIX_RELATIONSHIP]: '/confidence',
  },
  x_opencti_score: {
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_OCTI}/score`,
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI_SCO}/score`,
    [ENTITY_TYPE_IDENTITY_ORGANIZATION]: `/extensions/${STIX_EXT_OCTI}/score`,
  },
  x_opencti_detection: {
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_OCTI}/detection`,
  },
  x_opencti_workflow_id: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
  },
  severity: {
    [ENTITY_TYPE_CONTAINER_CASE]: '/severity',
    [ENTITY_TYPE_INCIDENT]: '/severity',
  },
  priority: {
    [ENTITY_TYPE_CONTAINER_CASE]: '/priority',
  },
  indicator_types: {
    [ENTITY_TYPE_INDICATOR]: '/indicator_types',
  },
  [INPUT_KILLCHAIN]: {
    [ENTITY_TYPE_INDICATOR]: '/kill_chain_phases',
  },
  x_mitre_platforms: {
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_MITRE}/platforms`,
  },
};
interface UpdateValueConfiguration {
  label: string;
  value: string;
  patch_value: string;
}
interface UpdateConfiguration {
  actions: { op: 'add' | 'replace' | 'remove'; attribute: string; value: UpdateValueConfiguration[] }[];
  all: boolean;
}
const PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA: JSONSchemaType<UpdateConfiguration> = {
  type: 'object',
  properties: {
    actions: {
      type: 'array',
      default: [],
      items: {
        type: 'object',
        properties: {
          op: { type: 'string', enum: ['add', 'replace', 'remove'] },
          attribute: { type: 'string' },
          value: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                label: { type: 'string' },
                value: { type: 'string' },
                patch_value: { type: 'string' },
              },
              required: ['label', 'value', 'patch_value'],
            },
          },
        },
        required: ['op', 'attribute', 'value'],
      },
    },
    all: { type: 'boolean', $ref: 'Manipulate all elements included in the bundle', default: false },
  },
  required: ['actions'],
};
const PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT: PlaybookComponent<UpdateConfiguration> = {
  id: 'PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT',
  name: 'Manipulate knowledge',
  description: 'Manipulate STIX data',
  icon: 'edit',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const cacheIds = await getEntitiesMapFromCache(context, AUTOMATION_MANAGER_USER, ENTITY_TYPE_MARKING_DEFINITION);
    const { actions, all } = playbookNode.configuration;
    // Compute if the attribute is defined as multiple in schema definition
    const isAttributeMultiple = (entityType: string, attribute: string) => {
      const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
      if (baseAttribute) return baseAttribute.multiple;
      const relationRef = schemaRelationsRefDefinition.getRelationRef(entityType, attribute);
      if (relationRef) return relationRef.multiple;
      return undefined;
    };
    const getAttributeType = (entityType: string, attribute: string) => {
      const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
      return baseAttribute?.type ?? 'string';
    };
    // Compute the access path for the attribute in the static matrix
    const computeAttributePath = (entityType: string, attribute: string) => {
      if (attributePathMapping[attribute]) {
        if (attributePathMapping[attribute][entityType]) {
          return attributePathMapping[attribute][entityType];
        }
        const key = Object.keys(attributePathMapping[attribute]).filter((o) => getParentTypes(entityType).includes(o)).at(0);
        if (key) {
          return attributePathMapping[attribute][key];
        }
      }
      return undefined;
    };
    const convertValue = (attributeType: string, value: any) => {
      if (attributeType === 'numeric') return Number(value);
      if (attributeType === 'boolean') return value.toLowerCase() === 'true';
      return value;
    };
    const patchOperations = [];
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const element = bundle.objects[index];
      if (all || element.id === dataInstanceId) {
        const { type } = element.extensions[STIX_EXT_OCTI];
        const elementOperations = actions
          .map((action) => {
            const attrPath = computeAttributePath(type, action.attribute);
            const multiple = isAttributeMultiple(type, action.attribute);
            const attributeType = getAttributeType(type, action.attribute);
            return ({ action, multiple, attributeType, attrPath, path: `/objects/${index}${attrPath}` });
          })
          // Unrecognized attributes must be filtered
          .filter(({ attrPath, multiple }) => isNotEmptyField(multiple) && isNotEmptyField(attrPath))
          // Map actions to data patches
          .map(({ action, path, multiple, attributeType }) => {
            if (multiple) {
              const currentValues = jsonpatch.getValueByPointer(bundle, path) ?? [];
              const actionValues = action.value.map((o) => {
                // If value is an id, must be converted to standard_id has we work on stix bundle
                if (cacheIds.has(o.patch_value)) return (cacheIds.get(o.patch_value) as BasicStoreCommon).standard_id;
                // Else, just return the value
                return convertValue(attributeType, o.patch_value);
              });
              if (action.op === EditOperation.Add) {
                return { op: EditOperation.Replace, path, value: R.uniq([...currentValues, ...actionValues]) };
              }
              if (action.op === EditOperation.Replace) {
                return { op: EditOperation.Replace, path, value: actionValues };
              }
              if (action.op === EditOperation.Remove) {
                return { op: EditOperation.Replace, path, value: currentValues.filter((c: any) => !actionValues.includes(c)) };
              }
            }
            const currentValue = R.head(action.value)?.patch_value;
            return { op: action.op, path, value: convertValue(attributeType, currentValue) };
          });
        // Enlist operations to execute
        patchOperations.push(...elementOperations);
      }
    }
    // Apply operations if needed
    if (patchOperations.length > 0) {
      const patchedBundle = jsonpatch.applyPatch(structuredClone(bundle), patchOperations).newDocument;
      const diff = jsonpatch.compare(bundle, patchedBundle);
      if (isNotEmptyField(diff)) {
        return { output_port: 'out', bundle: patchedBundle };
      }
    }
    return { output_port: 'unmodified', bundle };
  },
};

const DATE_SEEN_RULE = 'seen_dates';
const RESOLVE_CONTAINER = 'resolve_container';
const RESOLVE_NEIGHBORS = 'resolve_neighbors';
const RESOLVE_INDICATORS = 'resolve_indicators';
const RESOLVE_OBSERVABLES = 'resolve_observables';
const RESOLVE_CONTAINER_CONTAINING = 'resolve_containers_containing';

type StixWithSeenDates = StixThreatActor | StixCampaign | StixIncident | StixInfrastructure | StixMalware;
const ENTITIES_DATE_SEEN_PREFIX = ['threat-actor--', 'campaign--', 'incident--', 'infrastructure--', 'malware--'];
type SeenFilter = { element: StixWithSeenDates; isImpactedBefore: boolean; isImpactedAfter: boolean };
interface RuleConfiguration {
  rule: string;
  inferences: boolean;
}
const PLAYBOOK_RULE_COMPONENT_SCHEMA: JSONSchemaType<RuleConfiguration> = {
  type: 'object',
  properties: {
    rule: {
      type: 'string',
      $ref: 'Rule to apply',
      oneOf: [
        { const: DATE_SEEN_RULE, title: 'First/Last seen computing extension from report publication date' },
        { const: RESOLVE_INDICATORS, title: 'Resolve indicators based on observables (add in bundle)' },
        { const: RESOLVE_OBSERVABLES, title: 'Resolve observables an indicator is based on (add in bundle)' },
        { const: RESOLVE_CONTAINER, title: 'Resolve container references (add in bundle)' },
        { const: RESOLVE_NEIGHBORS, title: 'Resolve neighbors relations and entities (add in bundle)' },
        { const: RESOLVE_CONTAINER_CONTAINING, title: 'Resolve containers containing the entity (add in bundle)' },
      ],
    },
    inferences: { type: 'boolean', $ref: 'Include inferred objects', default: false },
  },
  required: ['rule', 'inferences'],
};
const PLAYBOOK_RULE_COMPONENT: PlaybookComponent<RuleConfiguration> = {
  id: 'PLAYBOOK_RULE_COMPONENT',
  name: 'Apply predefined rule',
  description: 'Execute advanced predefined computing',
  icon: 'memory',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_RULE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_RULE_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const { id, type } = baseData.extensions[STIX_EXT_OCTI];
    const { rule, inferences } = playbookNode.configuration;
    if (rule === RESOLVE_INDICATORS) {
      // RESOLVE_INDICATORS is for now only triggered on observable creation / update
      if (isStixCyberObservable(type)) {
        // Observable <-- (based on) -- Indicator
        const relationOpts = { toId: id, fromTypes: [ENTITY_TYPE_INDICATOR], indices: inferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED };
        const basedOnRelations = await fullRelationsList<BasicStoreRelation>(context, AUTOMATION_MANAGER_USER, RELATION_BASED_ON, relationOpts);
        const targetIds = R.uniq(basedOnRelations.map((relation) => relation.fromId));
        if (targetIds.length > 0) {
          const indicators = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, targetIds) as StixObject[];
          bundle.objects.push(...indicators);
          return { output_port: 'out', bundle };
        }
      }
    }
    if (rule === RESOLVE_OBSERVABLES) {
      // RESOLVE_OBSERVABLES is for now only triggered on indicator creation / update
      if (type === ENTITY_TYPE_INDICATOR && isNotEmptyField(id)) {
        // Indicator (based on) --> Observable
        // eslint-disable-next-line max-len
        const relationOpts = { fromId: id, toTypes: [ABSTRACT_STIX_CYBER_OBSERVABLE], indices: inferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED };
        const basedOnRelations = await fullRelationsList<BasicStoreRelation>(context, AUTOMATION_MANAGER_USER, RELATION_BASED_ON, relationOpts);
        const targetIds = R.uniq(basedOnRelations.map((relation) => relation.fromId));
        if (targetIds.length > 0) {
          const observables = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, targetIds) as StixObject[];
          bundle.objects.push(...observables);
          return { output_port: 'out', bundle };
        }
      }
    }
    if (rule === DATE_SEEN_RULE) {
      // DATE_SEEN_RULE is only triggered on report creation / update
      if (type === ENTITY_TYPE_CONTAINER_REPORT) {
      // Handle first seen synchro for reports creation / modification
        const report = baseData as StixReport;
        const publicationDate = utcDate(report.published);
        const targetIds = (report.object_refs ?? [])
          .filter((o) => ENTITIES_DATE_SEEN_PREFIX.some((prefix) => o.startsWith(prefix)));
        if (targetIds.length > 0) {
          const elements = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, targetIds) as StixWithSeenDates[];
          const elementsToPatch = elements
            .map((e: StixWithSeenDates) => {
              // Check if seen dates will be impacted.
              const isImpactedBefore = isEmptyField(e.first_seen) || publicationDate.isBefore(e.first_seen);
              const isImpactedAfter = isEmptyField(e.last_seen) || publicationDate.isAfter(e.last_seen);
              return { element: e, isImpactedBefore, isImpactedAfter };
            })
            .filter((data: SeenFilter) => {
              return data.isImpactedBefore || data.isImpactedAfter;
            })
            .map((data: SeenFilter) => {
              const first_seen = data.isImpactedBefore ? publicationDate.toISOString() : data.element.first_seen;
              const last_seen = data.isImpactedAfter ? publicationDate.toISOString() : data.element.last_seen;
              return { ...data.element, first_seen, last_seen };
            });
          if (elementsToPatch.length > 0) {
            bundle.objects.push(...elementsToPatch);
            return { output_port: 'out', bundle };
          }
        }
      }
    }
    if (rule === RESOLVE_CONTAINER) {
      // DATE_SEEN_RULE is only triggered on report creation / update
      if (isStixDomainObjectContainer(type)) {
        // Handle first seen synchro for reports creation / modification
        const container = baseData as StixContainer;
        const objectRefsToResolve = [];
        const objectRefsWithoutMetas = container.object_refs?.filter((o) => !o.startsWith('relationship-meta'));
        if (objectRefsWithoutMetas && objectRefsWithoutMetas.length > 0) {
          objectRefsToResolve.push(...objectRefsWithoutMetas);
        }
        if (inferences && container.extensions[STIX_EXT_OCTI].object_refs_inferred && container.extensions[STIX_EXT_OCTI].object_refs_inferred.length > 0) {
          objectRefsToResolve.push(...container.extensions[STIX_EXT_OCTI].object_refs_inferred);
        }
        const elements = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, objectRefsToResolve) as StixObject[];
        if (elements.length > 0) {
          bundle.objects.push(...elements);
          return { output_port: 'out', bundle };
        }
      }
    }
    if (rule === RESOLVE_CONTAINER_CONTAINING) {
      const filters = {
        mode: FilterMode.And,
        filters: [{ key: ['objects'], values: [id] }],
        filterGroups: [],
      };
      const containers = await fullEntitiesList(context, AUTOMATION_MANAGER_USER, [ENTITY_TYPE_CONTAINER], { filters, baseData: true });
      const containersToResolve = containers.map((container) => container.id);
      const elements = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, containersToResolve) as StixObject[];
      if (elements.length > 0) {
        bundle.objects.push(...elements);
        return { output_port: 'out', bundle };
      }
    }
    if (rule === RESOLVE_NEIGHBORS) {
      const relations = await fullRelationsList(
        context,
        AUTOMATION_MANAGER_USER,
        ABSTRACT_STIX_CORE_RELATIONSHIP,
        { fromOrToId: id, baseData: true, indices: inferences ? READ_RELATIONSHIPS_INDICES : READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED },
      ) as StoreRelation[];
      let idsToResolve = R.uniq(
        [
          ...relations.map((r) => r.id),
          ...relations.map((r) => (id === r.fromId ? r.toId : r.fromId)),
        ],
      );
      // In case of relation, we also resolve the from and to
      const baseDataRelation = baseData as StixRelation;
      if (baseDataRelation.source_ref && baseDataRelation.target_ref) {
        idsToResolve = R.uniq([...idsToResolve, baseDataRelation.source_ref, baseDataRelation.target_ref]);
      }
      const elements = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, idsToResolve) as StixObject[];
      if (elements.length > 0) {
        bundle.objects.push(...elements);
        return { output_port: 'out', bundle };
      }
    }
    return { output_port: 'unmodified', bundle };
  },
};

export interface NotifierConfiguration {
  notifiers: string[];
  authorized_members: object;
}
const PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA: JSONSchemaType<NotifierConfiguration> = {
  type: 'object',
  properties: {
    notifiers: {
      type: 'array',
      uniqueItems: true,
      default: [],
      $ref: 'Notifiers',
      items: { type: 'string', oneOf: [] },
    },
    authorized_members: { type: 'object' },
  },
  required: ['notifiers', 'authorized_members'],
};
const PLAYBOOK_NOTIFIER_COMPONENT: PlaybookComponent<NotifierConfiguration> = {
  id: 'PLAYBOOK_NOTIFIER_COMPONENT',
  name: 'Send to notifier',
  description: 'Send user notification',
  icon: 'notification',
  is_entry_point: false,
  is_internal: true,
  ports: [],
  configuration_schema: PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const notifiers = await usableNotifiers(context, SYSTEM_USER);
    const elements = notifiers.map((c) => ({ const: c.id, title: c.name }));
    const schemaElement = { properties: { notifiers: { items: { oneOf: elements } } } };
    return R.mergeDeepRight<JSONSchemaType<NotifierConfiguration>, any>(PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ dataInstanceId, playbookId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const playbook = await storeLoadById<BasicStoreEntityPlaybook>(context, SYSTEM_USER, playbookId, ENTITY_TYPE_PLAYBOOK);
    const { notifiers, authorized_members } = playbookNode.configuration;
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const targetUsers = await convertMembersToUsers(authorized_members as { value: string }[], baseData, bundle);
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    const notificationsCall = [];
    for (let index = 0; index < targetUsers.length; index += 1) {
      const targetUser = targetUsers[index];
      const user_inside_platform_organization = isUserInPlatformOrganization(targetUser, settings);
      const userContext = { ...context, user_inside_platform_organization };
      const stixElements = bundle.objects.filter((o) => isUserCanAccessStixElement(userContext, targetUser, o));
      const notificationEvent: DigestEvent = {
        version: EVENT_NOTIFICATION_VERSION,
        playbook_source: playbook.name,
        notification_id: playbookNode.id,
        target: convertToNotificationUser(targetUser, notifiers),
        type: 'digest',
        data: stixElements.map((stixObject) => ({
          notification_id: playbookNode.id,
          instance: stixObject,
          type: 'create', // TODO Improve that with type event follow up
          message: generateCreateMessage({ ...stixObject, entity_type: convertStixToInternalTypes(stixObject.type) }) === '-' ? playbookNode.name : generateCreateMessage({ ...stixObject, entity_type: convertStixToInternalTypes(stixObject.type) }),
        })),
      };
      notificationsCall.push(storeNotificationEvent(context, notificationEvent));
    }
    if (notificationsCall.length > 0) {
      await Promise.all(notificationsCall);
    }
    return { output_port: undefined, bundle };
  },
};
interface CreateIndicatorConfiguration {
  all: boolean;
  wrap_in_container: boolean;
  types: string[];
}
const PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA: JSONSchemaType<CreateIndicatorConfiguration> = {
  type: 'object',
  properties: {
    types: {
      type: 'array',
      default: [],
      $ref: 'Types',
      items: { type: 'string', oneOf: [] },
    },
    all: { type: 'boolean', $ref: 'Create indicators from all observables in the bundle', default: false },
    wrap_in_container: { type: 'boolean', $ref: 'If main entity is a container, wrap indicators in container', default: false },
  },
  required: [],
};
const PLAYBOOK_CREATE_INDICATOR_COMPONENT: PlaybookComponent<CreateIndicatorConfiguration> = {
  id: 'PLAYBOOK_CREATE_INDICATOR_COMPONENT',
  name: 'Promote observable to indicator',
  description: 'Create an indicator based on an observable',
  icon: 'indicator',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA,
  schema: async () => {
    const types = schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE);
    const elements = types.map((t) => ({ const: t, title: t }))
      .sort((a, b) => (a.title.toLowerCase() > b.title.toLowerCase() ? 1 : -1));
    const schemaElement = { properties: { types: { items: { oneOf: elements } } } };
    return R.mergeDeepRight<JSONSchemaType<CreateIndicatorConfiguration>, any>(PLAYBOOK_CREATE_INDICATOR_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ playbookNode, dataInstanceId, bundle }) => {
    const { all, wrap_in_container, types } = playbookNode.configuration;
    const context = executionContext('playbook_components');
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const observables = [baseData];
    if (all) {
      observables.push(...bundle.objects);
    }
    const { type: baseDataType, id } = baseData.extensions[STIX_EXT_OCTI];
    const isBaseDataAContainer = isStixDomainObjectContainer(baseDataType);
    const objectsToPush: StixObject[] = [];
    for (let index = 0; index < observables.length; index += 1) {
      const observable = observables[index] as StixCyberObject;
      let { type } = observable.extensions[STIX_EXT_OCTI];
      if (isStixCyberObservable(type) && (isEmptyField(types) || types.includes(type))) {
        const indicatorName = observableValue({ ...observable, entity_type: type });
        const { key, value } = generateKeyValueForIndicator(type, indicatorName, observable);
        if (key.includes('Artifact')) {
          type = 'StixFile';
        }
        const pattern = await createStixPattern(context, AUTOMATION_MANAGER_USER, key, value);
        const score = observable.x_opencti_score ?? observable.extensions[STIX_EXT_OCTI_SCO]?.score;
        const { granted_refs } = observable.extensions[STIX_EXT_OCTI];
        if (pattern) {
          const indicatorData = {
            name: indicatorName,
            x_opencti_main_observable_type: type,
            x_opencti_score: score,
            pattern,
            pattern_type: STIX_PATTERN_TYPE,
            extensions: {
              [STIX_EXT_OCTI]: {
                extension_type: 'property-extension',
                type: ENTITY_TYPE_INDICATOR,
                main_observable_type: type,
                score,
              },
            },
          };
          const indicatorStandardId = generateStandardId(ENTITY_TYPE_INDICATOR, indicatorData);
          const storeIndicator = {
            internal_id: generateInternalId(),
            standard_id: indicatorStandardId,
            entity_type: ENTITY_TYPE_INDICATOR,
            parent_types: getParentTypes(ENTITY_TYPE_INDICATOR),
            ...indicatorData,
          } as StoreCommon;
          const indicator = convertStoreToStix_2_1(storeIndicator) as StixIndicator;
          if (observable.object_marking_refs) {
            indicator.object_marking_refs = observable.object_marking_refs;
          }
          if (observable.extensions[STIX_EXT_OCTI_SCO]?.labels) {
            indicator.labels = observable.extensions[STIX_EXT_OCTI_SCO].labels;
          }
          if (observable.extensions[STIX_EXT_OCTI_SCO]?.created_by_ref) {
            indicator.created_by_ref = observable.extensions[STIX_EXT_OCTI_SCO].created_by_ref;
          }
          if (observable.extensions[STIX_EXT_OCTI_SCO]?.external_references) {
            indicator.external_references = observable.extensions[STIX_EXT_OCTI_SCO].external_references;
          }
          if (granted_refs) {
            indicator.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
          }
          objectsToPush.push(indicator);
          if (wrap_in_container && isBaseDataAContainer) {
            (baseData as StixContainer).object_refs.push(indicator.id);
          }
          const relationBaseData = {
            source_ref: indicator.id,
            target_ref: observable.id,
            relationship_type: RELATION_BASED_ON,
          };
          const relationStandardId = idGenFromData('relationship', relationBaseData);
          const relationship = {
            id: relationStandardId,
            type: 'relationship',
            ...relationBaseData,
            object_marking_refs: observable.object_marking_refs ?? [],
            created: now(),
            modified: now(),
            extensions: {
              [STIX_EXT_OCTI]: {
                extension_type: 'property-extension',
                type: RELATION_BASED_ON,
              },
            },
          } as StixRelation;
          if (granted_refs) {
            relationship.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
          }
          objectsToPush.push(relationship);

          // Resolve relationships in the bundle
          const stixRelationshipsInBundle = bundle.objects.filter((r) => r.type === 'relationship') as StixRelation[];
          const stixRelationships = stixRelationshipsInBundle.filter((r) => r.relationship_type === 'related-to'
            && r.source_ref === baseData.id
            && (
              r.target_ref.startsWith('threat-actor')
              || r.target_ref.startsWith('intrusion-set')
              || r.target_ref.startsWith('campaign')
              || r.target_ref.startsWith('malware')
              || r.target_ref.startsWith('incident')
              || r.target_ref.startsWith('tool')
              || r.target_ref.startsWith('attack-pattern')
            ));
          for (let indexStixRelationships = 0; indexStixRelationships < stixRelationships.length; indexStixRelationships += 1) {
            const stixRelationship = stixRelationships[indexStixRelationships] as StixRelation;
            const relationIndicatesBaseData = {
              source_ref: indicator.id,
              target_ref: stixRelationship.target_ref,
              relationship_type: RELATION_INDICATES,
            };
            const relationIndicatesStandardId = idGenFromData('relationship', relationIndicatesBaseData);
            const relationshipIndicates = {
              id: relationIndicatesStandardId,
              type: 'relationship',
              ...relationIndicatesBaseData,
              object_marking_refs: observable.object_marking_refs ?? [],
              created: now(),
              modified: now(),
              extensions: {
                [STIX_EXT_OCTI]: {
                  extension_type: 'property-extension',
                  type: RELATION_INDICATES,
                },
              },
            } as StixRelation;
            if (granted_refs) {
              relationshipIndicates.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
            }
            objectsToPush.push(relationshipIndicates);
          }
          // Resolve relationships in database
          if (isNotEmptyField(id)) {
            const relationsOfObservables = await fullRelationsList(
              context,
              AUTOMATION_MANAGER_USER,
              ABSTRACT_STIX_CORE_RELATIONSHIP,
              {
                fromOrToId: id,
                toTypes: [
                  ENTITY_TYPE_THREAT_ACTOR,
                  ENTITY_TYPE_INTRUSION_SET,
                  ENTITY_TYPE_CAMPAIGN,
                  ENTITY_TYPE_MALWARE,
                  ENTITY_TYPE_INCIDENT,
                  ENTITY_TYPE_TOOL,
                  ENTITY_TYPE_ATTACK_PATTERN,
                ],
                baseData: true,
                indices: READ_RELATIONSHIPS_INDICES,
              },
            ) as StoreRelation[];
            const idsToResolve = R.uniq(relationsOfObservables.map((r) => r.toId));
            const elements = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, idsToResolve);
            for (let indexElements = 0; indexElements < elements.length; indexElements += 1) {
              const element = elements[indexElements] as StixCoreObject;
              const relationIndicatesBaseData = {
                source_ref: indicator.id,
                target_ref: element.id,
                relationship_type: RELATION_INDICATES,
              };
              const relationIndicatesStandardId = idGenFromData('relationship', relationIndicatesBaseData);
              const relationshipIndicates = {
                id: relationIndicatesStandardId,
                type: 'relationship',
                ...relationIndicatesBaseData,
                object_marking_refs: observable.object_marking_refs ?? [],
                created: now(),
                modified: now(),
                extensions: {
                  [STIX_EXT_OCTI]: {
                    extension_type: 'property-extension',
                    type: RELATION_INDICATES,
                  },
                },
              } as StixRelation;
              if (granted_refs) {
                relationshipIndicates.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
              }
              objectsToPush.push(relationshipIndicates);
            }
          }
          if (wrap_in_container && isBaseDataAContainer) {
            (baseData as StixContainer).object_refs.push(relationship.id);
          }
        }
      }
    }
    if (objectsToPush.length > 0) {
      bundle.objects.push(...objectsToPush);
      return { output_port: 'out', bundle: { ...bundle, objects: bundle.objects.map((n) => (n.id === baseData.id ? baseData : n)) } };
    }
    return { output_port: 'unmodified', bundle };
  },
};
interface CreateObservableConfiguration {
  all: boolean;
  wrap_in_container: boolean;
}
const PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA: JSONSchemaType<CreateObservableConfiguration> = {
  type: 'object',
  properties: {
    all: { type: 'boolean', $ref: 'Create observables from all indicators in the bundle', default: false },
    wrap_in_container: { type: 'boolean', $ref: 'If main entity is a container, wrap observables in container', default: false },
  },
  required: [],
};
const PLAYBOOK_CREATE_OBSERVABLE_COMPONENT: PlaybookComponent<CreateObservableConfiguration> = {
  id: 'PLAYBOOK_CREATE_OBSERVABLE_COMPONENT',
  name: 'Extract observables from indicator',
  description: 'Create observables based on an indicator',
  icon: 'observable',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_CREATE_OBSERVABLE_COMPONENT_SCHEMA,
  executor: async ({ playbookNode, dataInstanceId, bundle }) => {
    const { all, wrap_in_container } = playbookNode.configuration;
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const indicators = [baseData];
    if (all) {
      indicators.push(...bundle.objects);
    }
    const { type: baseDataType } = baseData.extensions[STIX_EXT_OCTI];
    const isBaseDataAContainer = isStixDomainObjectContainer(baseDataType);
    const objectsToPush: StixObject[] = [];
    for (let indexIndicator = 0; indexIndicator < indicators.length; indexIndicator += 1) {
      const indicator = indicators[indexIndicator] as StixIndicator;
      if (indicator.type === 'indicator') {
        const observables = extractValidObservablesFromIndicatorPattern(indicator.pattern);
        for (let indexObservable = 0; indexObservable < observables.length; indexObservable += 1) {
          const observable = observables[indexObservable];
          const description = indicator.description ?? `Simple observable of indicator {${indicator.name || indicator.pattern}}`;
          const { score, granted_refs } = indicator.extensions[STIX_EXT_OCTI];
          const observableData = {
            ...R.dissoc('type', observable),
            x_opencti_score: score,
            x_opencti_description: description,
            extensions: {
              [STIX_EXT_OCTI]: {
                extension_type: 'property-extension',
                type: observable.type,
              },
              [STIX_EXT_OCTI_SCO]: {
                extension_type: 'property-extension',
                score,
                description,
              },
            },
          };
          const observableStandardId = generateStandardId(observable.type, observableData);
          const storeObservable = {
            internal_id: generateInternalId(),
            standard_id: observableStandardId,
            entity_type: observable.type,
            parent_types: getParentTypes(observable.type),
            ...observableData,
          } as StoreCommon;
          const stixObservable = convertStoreToStix_2_1(storeObservable) as StixCyberObject;
          if (indicator.object_marking_refs) {
            stixObservable.object_marking_refs = indicator.object_marking_refs;
          }
          if (indicator.created_by_ref && stixObservable.extensions[STIX_EXT_OCTI_SCO]) {
            stixObservable.extensions[STIX_EXT_OCTI_SCO].created_by_ref = indicator.created_by_ref;
          }
          if (indicator.labels && stixObservable.extensions[STIX_EXT_OCTI_SCO]) {
            stixObservable.extensions[STIX_EXT_OCTI_SCO].labels = indicator.labels;
          }
          if (indicator.external_references && stixObservable.extensions[STIX_EXT_OCTI_SCO]) {
            stixObservable.extensions[STIX_EXT_OCTI_SCO].external_references = indicator.external_references;
          }
          if (granted_refs) {
            stixObservable.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
          }
          objectsToPush.push(stixObservable);
          if (wrap_in_container && isBaseDataAContainer) {
            (baseData as StixContainer).object_refs.push(stixObservable.id);
          }
          const relationBaseData = {
            source_ref: indicator.id,
            target_ref: stixObservable.id,
            relationship_type: RELATION_BASED_ON,
          };
          const relationStandardId = idGenFromData('relationship', relationBaseData);
          const relationship = {
            id: relationStandardId,
            type: 'relationship',
            ...relationBaseData,
            object_marking_refs: indicator.object_marking_refs ?? [],
            created: now(),
            modified: now(),
            extensions: {
              [STIX_EXT_OCTI]: {
                extension_type: 'property-extension',
                type: RELATION_BASED_ON,
              },
            },
          } as StixRelation;
          if (granted_refs) {
            relationship.extensions[STIX_EXT_OCTI].granted_refs = granted_refs;
          }
          objectsToPush.push(relationship);
          if (wrap_in_container && isBaseDataAContainer) {
            (baseData as StixContainer).object_refs.push(relationship.id);
          }
        }
      }
    }
    if (objectsToPush.length > 0) {
      bundle.objects.push(...objectsToPush);
      return { output_port: 'out', bundle: { ...bundle, objects: bundle.objects.map((n) => (n.id === baseData.id ? baseData : n)) } };
    }
    return { output_port: 'unmodified', bundle };
  },
};
// endregion

// @ts-expect-error TODO improve playbook types to avoid this
export const PLAYBOOK_COMPONENTS: { [k: string]: PlaybookComponent<object> } = {
  [PLAYBOOK_INTERNAL_MANUAL_TRIGGER.id]: PLAYBOOK_INTERNAL_MANUAL_TRIGGER,
  [PLAYBOOK_INTERNAL_DATA_STREAM.id]: PLAYBOOK_INTERNAL_DATA_STREAM,
  [PLAYBOOK_DATA_STREAM_PIR.id]: PLAYBOOK_DATA_STREAM_PIR,
  [PLAYBOOK_INTERNAL_DATA_CRON.id]: PLAYBOOK_INTERNAL_DATA_CRON,
  [PLAYBOOK_LOGGER_COMPONENT.id]: PLAYBOOK_LOGGER_COMPONENT,
  [PLAYBOOK_INGESTION_COMPONENT.id]: PLAYBOOK_INGESTION_COMPONENT,
  [PLAYBOOK_MATCHING_COMPONENT.id]: PLAYBOOK_MATCHING_COMPONENT,
  [PLAYBOOK_CONNECTOR_COMPONENT.id]: PLAYBOOK_CONNECTOR_COMPONENT,
  [PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT.id]: PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT,
  [PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.id]: PLAYBOOK_CONTAINER_WRAPPER_COMPONENT,
  [PLAYBOOK_SECURITY_COVERAGE_COMPONENT.id]: PLAYBOOK_SECURITY_COVERAGE_COMPONENT,
  [PLAYBOOK_SHARING_COMPONENT.id]: PLAYBOOK_SHARING_COMPONENT,
  [PLAYBOOK_UNSHARING_COMPONENT.id]: PLAYBOOK_UNSHARING_COMPONENT,
  [PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT.id]: PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT,
  [PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT.id]: PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT,
  [PLAYBOOK_RULE_COMPONENT.id]: PLAYBOOK_RULE_COMPONENT,
  [PLAYBOOK_NOTIFIER_COMPONENT.id]: PLAYBOOK_NOTIFIER_COMPONENT,
  [PLAYBOOK_CREATE_INDICATOR_COMPONENT.id]: PLAYBOOK_CREATE_INDICATOR_COMPONENT,
  [PLAYBOOK_REDUCING_COMPONENT.id]: PLAYBOOK_REDUCING_COMPONENT,
  [PLAYBOOK_CREATE_OBSERVABLE_COMPONENT.id]: PLAYBOOK_CREATE_OBSERVABLE_COMPONENT,
  [PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT.id]: PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT,
};

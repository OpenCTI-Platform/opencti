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
import type { JSONSchemaType } from 'ajv';
import { type BasicStoreEntityPlaybook, ENTITY_TYPE_PLAYBOOK, type PlaybookComponent } from './playbook-types';
import { AUTOMATION_MANAGER_USER, AUTOMATION_MANAGER_USER_UUID, executionContext, isUserCanAccessStixElement, isUserInPlatformOrganization, SYSTEM_USER } from '../../utils/access';
import { pushToConnector, pushToWorkerForConnector } from '../../database/rabbitmq';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, ENTITY_TYPE_CONTAINER } from '../../schema/general';
import type { BasicStoreRelation, StoreRelation } from '../../types/store';
import { generateInternalId, generateStandardId } from '../../schema/identifier';
import { utcDate } from '../../utils/format';
import type { StixCampaign, StixContainer, StixIncident, StixInfrastructure, StixMalware, StixReport, StixThreatActor } from '../../types/stix-2-1-sdo';
import { convertStixToInternalTypes, generateInternalType, getParentTypes } from '../../schema/schemaUtils';
import { ENTITY_TYPE_CONTAINER_REPORT, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import type { CyberObjectExtension, StixBundle, StixCyberObject, StixObject, StixOpenctiExtension } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../types/stix-2-1-extensions';
import { connectorsForPlaybook } from '../../database/repository';
import { fullEntitiesList, fullRelationsList, storeLoadById } from '../../database/middleware-loader';
import { getEntityFromCache } from '../../database/cache';
import { logApp } from '../../config/conf';
import { isEmptyField, isNotEmptyField, READ_RELATIONSHIPS_INDICES, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { stixLoadByIds } from '../../database/middleware';
import { usableNotifiers } from '../notifier/notifier-domain';
import { convertToNotificationUser, type DigestEvent, EVENT_NOTIFICATION_VERSION } from '../../manager/notificationManager';
import { storeNotificationEvent } from '../../database/stream/stream-handler';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { RELATION_BASED_ON } from '../../schema/stixCoreRelationship';
import type { StixRelation } from '../../types/stix-2-1-sro';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_CONTAINER_TASK, type StixTask, type StoreEntityTask } from '../task/task-types';
import { FilterMode } from '../../generated/graphql';
import { generateCreateMessage } from '../../database/data-changes';
import { findAllByCaseTemplateId } from '../task/task-domain';
import type { BasicStoreEntityTaskTemplate } from '../task/task-template/task-template-types';
import type { BasicStoreSettings } from '../../types/settings';
import { PLAYBOOK_SEND_EMAIL_TEMPLATE_COMPONENT } from './components/send-email-template-component';
import { convertMembersToUsers, extractBundleBaseElement } from './playbook-utils';
import { PLAYBOOK_DATA_STREAM_PIR } from './components/data-stream-pir-component';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { pushAll } from '../../utils/arrayUtil';
import { PLAYBOOK_CONTAINER_WRAPPER_COMPONENT } from './components/container-wrapper-component';
import { PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT } from './components/manipulate-knowledge-component';
import { PLAYBOOK_SECURITY_COVERAGE_COMPONENT } from './components/security-coverage-component';
import { PLAYBOOK_SHARING_COMPONENT } from './components/sharing-component';
import { PLAYBOOK_UNSHARING_COMPONENT } from './components/unsharing-component';
import { PLAYBOOK_ACCESS_RESTRICTIONS_COMPONENT } from './components/access-restrictions-component';
import { PLAYBOOK_REMOVE_ACCESS_RESTRICTIONS_COMPONENT } from './components/remove-access-restrictions-component';
import { PLAYBOOK_CREATE_INDICATOR_COMPONENT } from './components/create-indicator-component';
import { PLAYBOOK_CREATE_OBSERVABLE_COMPONENT } from './components/create-observable-component';

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
  canEnrollManually: boolean;
}
const PLAYBOOK_INTERNAL_DATA_STREAM_SCHEMA: JSONSchemaType<StreamConfiguration> = {
  type: 'object',
  properties: {
    create: { type: 'boolean', default: true },
    update: { type: 'boolean', default: false },
    delete: { type: 'boolean', default: false },
    filters: { type: 'string' },
    canEnrollManually: { type: 'boolean', default: true },
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
export const PLAYBOOK_REDUCING_COMPONENT: PlaybookComponent<ReduceConfiguration> = {
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
    const matchedElements = [];
    for (let index = 0; index < bundle.objects.length; index += 1) {
      const bundleElement = bundle.objects[index];
      const isMatch = await isStixMatchFilterGroup(context, SYSTEM_USER, bundleElement, jsonFilters);
      if (isMatch) {
        matchedElements.push(bundleElement);
      }
    }
    if (matchedElements.length === 0) {
      return { output_port: 'unmatch', bundle };
    }
    // always add main entity to the final bundle if not already in it
    if (matchedElements.length > 0 && !matchedElements.some((e) => e.id === baseData.id)) {
      matchedElements.push(baseData);
    }
    return { output_port: 'out', bundle: { ...bundle, objects: matchedElements } };
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
export const PLAYBOOK_CONNECTOR_COMPONENT: PlaybookComponent<ConnectorConfiguration> = {
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
  notify: async ({ executionId, eventId, playbookId, playbookNode, previousPlaybookNodeId, dataInstanceId, bundle }) => {
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
  executor: async ({ bundle, previousStepBundle }) => {
    // Add extensions if needed
    // This is needed as the rest of playbook expecting STIX2.1 format with extensions
    const stixBundle = extendsBundleElementsWithExtensions(bundle);
    const resolveDuplicate = (a: any, b: any) => {
      if (Array.isArray(a) && Array.isArray(b)) {
        return R.uniq([...a, ...b]);
      }
      return b;
    };
    if (previousStepBundle) {
      const previousObjectsIndex: Record<string, StixObject> = {};
      previousStepBundle.objects.forEach((obj) => {
        previousObjectsIndex[obj.id] = obj;
      });
      // Check if new bundle objects has the same object ids of previous bundle objects
      const enrichedObjects = stixBundle.objects.map((newObj) => {
        const prevObj = previousObjectsIndex[newObj.id];
        if (prevObj) {
          // Merge both objects if same ids
          return R.mergeDeepWith<StixObject, StixObject>(resolveDuplicate, prevObj, newObj);
        }
        return newObj;
      });

      // Check if new bundle contains objects of previous bundle and add them if not in it
      const existingIds = new Set(stixBundle.objects.map((o) => o.id));
      const missingObjects = previousStepBundle.objects.filter(
        (prevObj) => !existingIds.has(prevObj.id),
      );
      if (missingObjects.length > 0) {
        pushAll(enrichedObjects, missingObjects);
      }
      stixBundle.objects = enrichedObjects;
      return { output_port: 'out', bundle: stixBundle };
    }
    return { output_port: 'out', bundle: stixBundle };
  },
};

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

export const createTaskFromCaseTemplates = async (
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
          pushAll(bundle.objects, indicators);
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
          pushAll(bundle.objects, observables);
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
            pushAll(bundle.objects, elementsToPatch);
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
        const objectRefsToResolve: string[] = [];
        const objectRefsWithoutMetas = container.object_refs?.filter((o) => !o.startsWith('relationship-meta'));
        if (objectRefsWithoutMetas && objectRefsWithoutMetas.length > 0) {
          pushAll(objectRefsToResolve, objectRefsWithoutMetas);
        }
        if (inferences && container.extensions[STIX_EXT_OCTI].object_refs_inferred && container.extensions[STIX_EXT_OCTI].object_refs_inferred.length > 0) {
          pushAll(objectRefsToResolve, container.extensions[STIX_EXT_OCTI].object_refs_inferred);
        }
        const elements = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, objectRefsToResolve) as StixObject[];
        if (elements.length > 0) {
          pushAll(bundle.objects, elements);
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
        pushAll(bundle.objects, elements);
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
        pushAll(bundle.objects, elements);
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
  [PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT.id]: PLAYBOOK_MANIPULATE_KNOWLEDGE_COMPONENT,
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

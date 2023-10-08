/*
Copyright (c) 2021-2023 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Non-Commercial License (the "License");
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
import { type PlaybookComponent, type PlaybookComponentConfiguration, type BasicStoreEntityPlaybook, ENTITY_TYPE_PLAYBOOK } from './playbook-types';
import { convertFiltersFrontendFormat, isStixMatchFilters } from '../../utils/filtering';
import {
  AUTOMATION_MANAGER_USER,
  AUTOMATION_MANAGER_USER_UUID,
  executionContext,
  INTERNAL_USERS, isUserCanAccessStixElement,
  SYSTEM_USER
} from '../../utils/access';
import { pushToConnector, pushToPlaybook } from '../../database/rabbitmq';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER,
  INPUT_CREATED_BY,
  INPUT_LABELS,
  INPUT_MARKINGS,
} from '../../schema/general';
import { loadConnectorById } from '../../domain/connector';
import { convertStoreToStix } from '../../database/stix-converter';
import type { StoreCommon } from '../../types/store';
import { generateStandardId } from '../../schema/identifier';
import { now, utcDate } from '../../utils/format';
import { STIX_SPEC_VERSION } from '../../database/stix';
import type {
  StixCampaign,
  StixContainer,
  StixIncident,
  StixInfrastructure,
  StixMalware,
  StixReport,
  StixThreatActor
} from '../../types/stix-sdo';
import { getParentTypes } from '../../schema/schemaUtils';
import {
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INDICATOR,
  isStixDomainObjectContainer
} from '../../schema/stixDomainObject';
import type { StixBundle, StixCoreObject, StixObject } from '../../types/stix-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../types/stix-extensions';
import { connectorsForPlaybook } from '../../database/repository';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { listAllEntities, storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntityOrganization } from '../organization/organization-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { getEntitiesListFromCache } from '../../database/cache';
import { createdBy, objectLabel, objectMarking } from '../../schema/stixRefRelationship';
import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { extractStixRepresentative } from '../../database/stix-representative';
import {
  isEmptyField,
  isNotEmptyField,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
  UPDATE_OPERATION_REPLACE
} from '../../database/utils';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { stixLoadByIds } from '../../database/middleware';
import { usableNotifiers } from '../notifier/notifier-domain';
import {
  convertToNotificationUser,
  type DigestEvent,
  EVENT_NOTIFICATION_VERSION,
} from '../../manager/notificationManager';
import { storeNotificationEvent } from '../../database/redis';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthUser } from '../../types/user';

const extractBundleBaseElement = (instanceId: string, bundle: StixBundle): StixObject => {
  const baseData = bundle.objects.find((o) => o.id === instanceId);
  if (!baseData) throw FunctionalError('Playbook base element no longer accessible');
  return baseData;
};

// region built in playbook components
interface LoggerConfiguration extends PlaybookComponentConfiguration {
  level: string
}
const PLAYBOOK_LOGGER_COMPONENT_SCHEMA: JSONSchemaType<LoggerConfiguration> = {
  type: 'object',
  properties: {
    level: { type: 'string', default: 'debug', oneOf: [{ const: 'debug', title: 'debug' }, { const: 'info', title: 'info' }, { const: 'warning', title: 'warning' }, { const: 'error', title: 'error' }] },
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
    switch (playbookNode.configuration.level) {
      case 'info':
        logApp.info('[PLAYBOOK MANAGER] Logger component output', { bundle });
        break;
      case 'warning':
        logApp.warn('[PLAYBOOK MANAGER] Logger component output', { bundle });
        break;
      case 'error':
        logApp.error('[PLAYBOOK MANAGER] Logger component output', { bundle });
        break;
      default:
        logApp.debug('[PLAYBOOK MANAGER] Logger component output', { bundle });
    }
    return { output_port: 'out', bundle };
  }
};

export interface StreamConfiguration extends PlaybookComponentConfiguration {
  create: boolean,
  update: boolean,
  delete: boolean
}
const PLAYBOOK_INTERNAL_DATA_STREAM_SCHEMA: JSONSchemaType<StreamConfiguration> = {
  type: 'object',
  properties: {
    create: { type: 'boolean', default: true },
    update: { type: 'boolean', default: false },
    delete: { type: 'boolean', default: false },
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
    return ({ output_port: 'out', bundle });
  }
};

interface IngestionConfiguration extends PlaybookComponentConfiguration {}
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
  executor: async ({ bundle }) => {
    const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
    await pushToPlaybook({ type: 'bundle', applicant_id: AUTOMATION_MANAGER_USER_UUID, content, update: true });
    return { output_port: undefined, bundle };
  }
};

interface FilterConfiguration extends PlaybookComponentConfiguration {
  filters: string
}
const PLAYBOOK_FILTERING_COMPONENT_SCHEMA: JSONSchemaType<FilterConfiguration> = {
  type: 'object',
  properties: {
    filters: { type: 'string' },
  },
  required: ['filters'],
};
const PLAYBOOK_FILTERING_COMPONENT: PlaybookComponent<FilterConfiguration> = {
  id: 'PLAYBOOK_FILTERING_COMPONENT',
  name: 'Filter knowledge',
  description: 'Filter STIX data',
  icon: 'filter',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'empty', type: 'out' }],
  configuration_schema: PLAYBOOK_FILTERING_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_FILTERING_COMPONENT_SCHEMA,
  executor: async ({ playbookNode, dataInstanceId, bundle }) => {
    const context = executionContext('playbook_components');
    const jsonFilters = JSON.parse(playbookNode.configuration.filters);
    const adaptedFilters = await convertFiltersFrontendFormat(context, SYSTEM_USER, jsonFilters);
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const isMatch = await isStixMatchFilters(context, SYSTEM_USER, baseData, adaptedFilters);
    return { output_port: isMatch ? 'out' : 'empty', bundle };
  }
};

interface ConnectorConfiguration extends PlaybookComponentConfiguration {
  connector: string
}
const PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA: JSONSchemaType<ConnectorConfiguration> = {
  type: 'object',
  properties: {
    connector: { type: 'string', oneOf: [] },
  },
  required: ['connector'],
};
const PLAYBOOK_CONNECTOR_COMPONENT: PlaybookComponent<ConnectorConfiguration> = {
  id: 'PLAYBOOK_CONNECTOR_COMPONENT',
  name: 'Enrich through connector',
  description: 'Use a registered platform connector for enrichment',
  icon: 'connector',
  is_entry_point: false,
  is_internal: false,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const connectors = await connectorsForPlaybook(context, SYSTEM_USER);
    const elements = connectors.map((c) => ({ const: c.id, title: c.name }))
      .sort((a, b) => (a.title.toLowerCase() > b.title.toLowerCase() ? 1 : -1));
    const schemaElement = { properties: { connector: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<ConnectorConfiguration>, any>(PLAYBOOK_CONNECTOR_COMPONENT_SCHEMA, schemaElement);
  },
  notify: async ({ executionId, playbookId, playbookNode, previousPlaybookNode, dataInstanceId, bundle }) => {
    const context = executionContext('playbook_manager');
    const connector = await loadConnectorById(context, SYSTEM_USER, playbookNode.configuration.connector);
    const message = {
      internal: {
        work_id: null, // No work id associated
        playbook: {
          execution_id: executionId,
          playbook_id: playbookId,
          data_instance_id: dataInstanceId,
          step_id: playbookNode.id,
          previous_step_id: previousPlaybookNode?.id,
        },
        applicant_id: AUTOMATION_MANAGER_USER.id, // System user is responsible for the automation
      },
      event: {
        entity_id: dataInstanceId,
        bundle
      },
    };
    await pushToConnector(context, connector, message);
  },
  executor: async ({ bundle }) => {
    // Nothing to check on the follow up connector execution
    // Could be interesting to check if the bundle has changed in the future to forward to a different port
    return { output_port: 'out', bundle };
  }
};

interface ContainerWrapperConfiguration extends PlaybookComponentConfiguration {
  container_type: string
}
const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA: JSONSchemaType<ContainerWrapperConfiguration> = {
  type: 'object',
  properties: {
    container_type: { type: 'string', default: '', oneOf: [] }
  },
  required: ['container_type'],
};
const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT: PlaybookComponent<ContainerWrapperConfiguration> = {
  id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
  name: 'Container wrapper',
  description: 'Create a container and wrap the element inside it',
  icon: 'container',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA,
  schema: async () => {
    const entityTypes = schemaTypesDefinition.get(ENTITY_TYPE_CONTAINER);
    const elements = entityTypes.map((c) => ({ const: c, title: c }));
    const schemaElement = { properties: { container_type: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<ContainerWrapperConfiguration>, any>(PLAYBOOK_CONTAINER_WRAPPER_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const created = now();
    const containerType = playbookNode.configuration.container_type;
    if (isStixDomainObjectContainer(containerType)) {
      const baseData = extractBundleBaseElement(dataInstanceId, bundle);
      const containerData = {
        name: extractStixRepresentative(baseData) ?? `Generated container wrapper from playbook at ${created}`,
        created,
        published: created,
      };
      const standardId = generateStandardId(containerType, containerData);
      const storeContainer = {
        internal_id: uuidv4(),
        standard_id: standardId,
        entity_type: containerType,
        spec_version: STIX_SPEC_VERSION,
        parent_types: getParentTypes(containerType),
        ...containerData
      } as StoreCommon;
      const container = convertStoreToStix(storeContainer) as StixContainer;
      container.object_refs = [baseData.id];
      bundle.objects.push(container);
    }
    return { output_port: 'out', bundle };
  }
};

interface SharingConfiguration extends PlaybookComponentConfiguration {
  organizations: string[]
  operation: 'add' | 'remove' | 'replace'
}
const PLAYBOOK_SHARING_COMPONENT_SCHEMA: JSONSchemaType<SharingConfiguration> = {
  type: 'object',
  properties: {
    organizations: {
      type: 'array',
      uniqueItems: true,
      default: [],
      items: { type: 'string', oneOf: [] }
    },
    operation: { type: 'string', default: 'add', oneOf: [{ const: 'add', title: 'Add' }, { const: 'remove', title: 'Remove' }, { const: 'replace', title: 'Replace' }] },
  },
  required: ['organizations', 'operation'],
};
const PLAYBOOK_SHARING_COMPONENT: PlaybookComponent<SharingConfiguration> = {
  id: 'PLAYBOOK_SHARING_COMPONENT',
  name: 'Manage sharing with organizations',
  description: 'Share/Unshare with organizations within the platform',
  icon: 'identity',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_SHARING_COMPONENT_SCHEMA,
  schema: async () => {
    const context = executionContext('playbook_components');
    const organizations = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_ORGANIZATION], { connectionFormat: false });
    const elements = organizations.map((c) => ({ const: c.id, title: c.name }));
    const schemaElement = { properties: { organizations: { items: { oneOf: elements } } } };
    return R.mergeDeepRight<JSONSchemaType<SharingConfiguration>, any>(PLAYBOOK_SHARING_COMPONENT_SCHEMA, schemaElement);
  },
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const allOrganizations = await getEntitiesListFromCache<BasicStoreEntityOrganization>(context, SYSTEM_USER, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    const { organizations, operation } = playbookNode.configuration;
    const organizationIds = allOrganizations
      .filter((o) => (organizations ?? []).includes(o.internal_id))
      .map((o) => o.standard_id);
    const baseData = bundle.objects.find((o) => o.id === dataInstanceId) as StixCoreObject;
    // granted_refs are always fully change on absorption level
    // We only need to compute the expected final result
    if (operation === UPDATE_OPERATION_ADD) {
      baseData.extensions[STIX_EXT_OCTI].granted_refs = [...(baseData.extensions[STIX_EXT_OCTI].granted_refs ?? []), ...organizationIds];
    }
    if (operation === UPDATE_OPERATION_REMOVE && organizationIds.length > 0) {
      // noinspection UnnecessaryLocalVariableJS
      const remainingOrganizations = (baseData.extensions[STIX_EXT_OCTI].granted_refs ?? [])
        .filter((o: string) => organizationIds.some((select) => o !== select));
      baseData.extensions[STIX_EXT_OCTI].granted_refs = remainingOrganizations;
    }
    if (operation === UPDATE_OPERATION_REPLACE) {
      baseData.extensions[STIX_EXT_OCTI].granted_refs = organizationIds;
    }
    return { output_port: 'out', bundle };
  }
};

const attributePathMapping: any = {
  [INPUT_MARKINGS]: {
    [ABSTRACT_STIX_CORE_OBJECT]: `/${objectMarking.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${objectMarking.stixName}`,
  },
  [INPUT_LABELS]: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/${objectLabel.stixName}`,
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI_SCO}/${objectLabel.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${objectLabel.stixName}`,
  },
  [INPUT_CREATED_BY]: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/${createdBy.stixName}`,
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI_SCO}/${createdBy.stixName}`,
    [ABSTRACT_STIX_RELATIONSHIP]: `/${createdBy.stixName}`,
  },
  confidence: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: '/confidence',
    [ABSTRACT_STIX_RELATIONSHIP]: '/confidence',
  },
  x_opencti_score: {
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_OCTI}/score`,
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI_SCO}/score`,
  },
  x_opencti_detection: {
    [ENTITY_TYPE_INDICATOR]: `/extensions/${STIX_EXT_OCTI}/detection`,
  },
  x_opencti_workflow_id: {
    [ABSTRACT_STIX_DOMAIN_OBJECT]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
    [ABSTRACT_STIX_CYBER_OBSERVABLE]: `/extensions/${STIX_EXT_OCTI}/workflow_id`,
  }
};
interface UpdateValueConfiguration {
  label: string
  value: string
  patch_value: string
}
interface UpdateConfiguration extends PlaybookComponentConfiguration {
  actions: { op: 'add' | 'replace' | 'remove', attribute: string, value: UpdateValueConfiguration[] }[]
}
const PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA: JSONSchemaType<UpdateConfiguration> = {
  type: 'object',
  properties: {
    actions: {
      type: 'array',
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
                patch_value: { type: 'string' }
              },
              required: ['label', 'value', 'patch_value'],
            }
          },
        },
        required: ['op', 'attribute', 'value'],
      }
    },
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
  ports: [{ id: 'out', type: 'out' }, { id: 'not-impacted', type: 'out' }],
  configuration_schema: PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const { actions } = playbookNode.configuration;
    // Compute if the attribute is defined as multiple in schema definition
    const isAttributeMultiple = (entityType:string, attribute: string) => {
      const baseAttribute = schemaAttributesDefinition.getAttribute(entityType, attribute);
      if (baseAttribute) return baseAttribute.multiple;
      const relationRef = schemaRelationsRefDefinition.getRelationRef(entityType, attribute);
      if (relationRef) return relationRef.multiple;
      return undefined;
    };
    // Compute the access path for the attribute in the static matrix
    const computeAttributePath = (entityType:string, attribute: string) => {
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
    const { type } = baseData.extensions[STIX_EXT_OCTI];
    const standardOperations = actions
      .map((action) => ({ action, multiple: isAttributeMultiple(type, action.attribute), path: computeAttributePath(type, action.attribute) }))
      .filter(({ path, multiple }) => multiple !== undefined && isNotEmptyField(path))
      .map(({ action, path, multiple }) => ({ op: action.op, path, value: multiple ? action.value.map((o) => o.patch_value) : R.head(action.value)?.patch_value }));
    if (standardOperations.length > 0) {
      jsonpatch.applyPatch(baseData, standardOperations);
      return { output_port: 'out', bundle };
    }
    return { output_port: 'unmodified', bundle };
  }
};

const DATE_SEEN_RULE = 'seen_dates';
type StixWithSeenDates = StixThreatActor | StixCampaign | StixIncident | StixInfrastructure | StixMalware;
const ENTITIES_DATE_SEEN_PREFIX = ['threat-actor--', 'campaign--', 'incident--', 'infrastructure--', 'malware--'];
type SeenFilter = { element: StixWithSeenDates, isImpactedBefore: boolean, isImpactedAfter: boolean };
interface RuleConfiguration extends PlaybookComponentConfiguration {
  rule: string
}
const PLAYBOOK_RULE_COMPONENT_SCHEMA: JSONSchemaType<RuleConfiguration> = {
  type: 'object',
  properties: {
    rule: { type: 'string', oneOf: [{ const: DATE_SEEN_RULE, title: 'First/Last seen computing extension from report publication date' }] },
  },
  required: ['rule'],
};
const PLAYBOOK_RULE_COMPONENT: PlaybookComponent<RuleConfiguration> = {
  id: 'PLAYBOOK_RULE_COMPONENT',
  name: 'Execute predefined rule',
  description: 'Execute complex predefined computing',
  icon: 'memory',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'not-impacted', type: 'out' }],
  configuration_schema: PLAYBOOK_RULE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_RULE_COMPONENT_SCHEMA,
  executor: async ({ dataInstanceId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const baseData = extractBundleBaseElement(dataInstanceId, bundle);
    const { type } = baseData.extensions[STIX_EXT_OCTI];
    const { rule } = playbookNode.configuration;
    if (rule === DATE_SEEN_RULE) {
      // DATE_SEEN_RULE is only triggered on report creation / update
      if (type === ENTITY_TYPE_CONTAINER_REPORT) {
      // Handle first seen synchro for reports creation / modification
        const report = baseData as StixReport;
        const publicationDate = utcDate(report.published);
        const targetIds = (report.object_refs ?? [])
          .filter((o) => ENTITIES_DATE_SEEN_PREFIX.some((prefix) => o.startsWith(prefix)));
        if (targetIds.length > 0) {
          const elements = await stixLoadByIds(context, AUTOMATION_MANAGER_USER, targetIds);
          const elementsToPatch = elements
            .map((e: StixWithSeenDates) => {
              // Check if seen dates will be impacted.
              const isImpactedBefore = publicationDate.isBefore(e.first_seen ? utcDate(e.first_seen) : utcDate());
              const isImpactedAfter = publicationDate.isAfter(e.last_seen ? utcDate(e.last_seen) : utcDate());
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
    return { output_port: 'unmodified', bundle };
  }
};

const convertAuthorizedMemberToUsers = async (authorized_members: { value: string }[]) => {
  if (isEmptyField(authorized_members)) {
    return [];
  }
  const context = executionContext('playbook_components');
  const platformUsers = await getEntitiesListFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const triggerAuthorizedMembersIds = authorized_members?.map((member) => member.value) ?? [];
  const usersFromGroups = platformUsers.filter((user) => user.groups.map((g) => g.internal_id)
    .some((id: string) => triggerAuthorizedMembersIds.includes(id)));
  const usersFromOrganizations = platformUsers.filter((user) => user.organizations.map((g) => g.internal_id)
    .some((id: string) => triggerAuthorizedMembersIds.includes(id)));
  const usersFromIds = platformUsers.filter((user) => triggerAuthorizedMembersIds.includes(user.id));
  const withoutInternalUsers = [...usersFromOrganizations, ...usersFromGroups, ...usersFromIds]
    .filter((u) => INTERNAL_USERS[u.id] === undefined);
  return R.uniqBy(R.prop('id'), withoutInternalUsers);
};
export interface NotifierConfiguration extends PlaybookComponentConfiguration {
  notifiers: string[]
  authorized_members: object
}
const PLAYBOOK_NOTIFIER_COMPONENT_SCHEMA: JSONSchemaType<NotifierConfiguration> = {
  type: 'object',
  properties: {
    notifiers: {
      type: 'array',
      uniqueItems: true,
      default: [],
      items: { type: 'string', oneOf: [] }
    },
    authorized_members: { type: 'object' },
  },
  required: ['notifiers', 'authorized_members'],
};
const PLAYBOOK_NOTIFIER_COMPONENT: PlaybookComponent<NotifierConfiguration> = {
  id: 'PLAYBOOK_NOTIFIER_COMPONENT',
  name: 'Execute notifier',
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
  executor: async ({ playbookId, playbookNode, bundle }) => {
    const context = executionContext('playbook_components');
    const playbook = await storeLoadById<BasicStoreEntityPlaybook>(context, SYSTEM_USER, playbookId, ENTITY_TYPE_PLAYBOOK);
    const { notifiers, authorized_members } = playbookNode.configuration;
    const targetUsers = await convertAuthorizedMemberToUsers(authorized_members as { value: string }[]);
    for (let index = 0; index < targetUsers.length; index += 1) {
      const targetUser = targetUsers[index];
      const stixElements = bundle.objects.filter((o) => isUserCanAccessStixElement(context, targetUser, o));
      const notificationEvent: DigestEvent = {
        version: EVENT_NOTIFICATION_VERSION,
        playbook_source: playbook.name,
        notification_id: playbookNode.id,
        target: convertToNotificationUser(targetUser, notifiers),
        type: 'digest',
        data: stixElements.map((stixObject) => ({
          notification_id: playbookNode.id,
          instance: stixObject,
          type: 'create',
          message: `\`${playbookNode.name}\``
        }))
      };
      await storeNotificationEvent(context, notificationEvent);
    }
    return { output_port: undefined, bundle };
  }
};
// endregion

export const PLAYBOOK_COMPONENTS: { [k: string]: PlaybookComponent<any> } = {
  [PLAYBOOK_INTERNAL_DATA_STREAM.id]: PLAYBOOK_INTERNAL_DATA_STREAM,
  [PLAYBOOK_LOGGER_COMPONENT.id]: PLAYBOOK_LOGGER_COMPONENT,
  [PLAYBOOK_INGESTION_COMPONENT.id]: PLAYBOOK_INGESTION_COMPONENT,
  [PLAYBOOK_FILTERING_COMPONENT.id]: PLAYBOOK_FILTERING_COMPONENT,
  [PLAYBOOK_CONNECTOR_COMPONENT.id]: PLAYBOOK_CONNECTOR_COMPONENT,
  [PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT.id]: PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT,
  [PLAYBOOK_CONNECTOR_COMPONENT.id]: PLAYBOOK_CONNECTOR_COMPONENT,
  [PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.id]: PLAYBOOK_CONTAINER_WRAPPER_COMPONENT,
  [PLAYBOOK_SHARING_COMPONENT.id]: PLAYBOOK_SHARING_COMPONENT,
  [PLAYBOOK_RULE_COMPONENT.id]: PLAYBOOK_RULE_COMPONENT,
  [PLAYBOOK_NOTIFIER_COMPONENT.id]: PLAYBOOK_NOTIFIER_COMPONENT
};

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
import type { Operation } from 'fast-json-patch';
import type { PlaybookComponent, PlaybookComponentConfiguration } from './playbook-types';
import { convertFiltersFrontendFormat, isStixMatchFilters } from '../../utils/filtering';
import { AUTOMATION_MANAGER_USER, AUTOMATION_MANAGER_USER_UUID, executionContext, SYSTEM_USER } from '../../utils/access';
import { pushToConnector, pushToSync } from '../../database/rabbitmq';
import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER, INPUT_CREATED_BY,
  INPUT_LABELS,
  INPUT_MARKINGS,
} from '../../schema/general';
import { loadConnectorById } from '../../domain/connector';
import { convertStoreToStix } from '../../database/stix-converter';
import type { StoreCommon } from '../../types/store';
import { generateStandardId } from '../../schema/identifier';
import { now } from '../../utils/format';
import { STIX_SPEC_VERSION } from '../../database/stix';
import type { StixContainer } from '../../types/stix-sdo';
import { getParentTypes } from '../../schema/schemaUtils';
import { ENTITY_TYPE_INDICATOR, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import type { StixCoreObject } from '../../types/stix-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from '../../types/stix-extensions';
import { connectorsForPlaybook } from '../../database/repository';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { listAllEntities } from '../../database/middleware-loader';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import type { BasicStoreEntityOrganization } from '../organization/organization-types';
import { getEntitiesListFromCache } from '../../database/cache';
import { createdBy, objectLabel, objectMarking } from '../../schema/stixRefRelationship';
import { logApp } from '../../config/conf';

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
  executor: async ({ bundle, instance }) => {
    switch (instance.configuration.level) {
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
    await pushToSync({ type: 'bundle', applicant_id: AUTOMATION_MANAGER_USER_UUID, content, update: true });
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
  executor: async ({ instance, instanceId, bundle }) => {
    const context = executionContext('playbook_components');
    const jsonFilters = JSON.parse(instance.configuration.filters);
    const adaptedFilters = await convertFiltersFrontendFormat(context, SYSTEM_USER, jsonFilters);
    const baseData = bundle.objects.find((o) => o.id === instanceId);
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
  notify: async ({ playbookId, instance, previousInstance, instanceId, bundle }) => {
    const context = executionContext('playbook_manager');
    const connector = await loadConnectorById(context, SYSTEM_USER, instance.configuration.connector);
    const message = {
      internal: {
        work_id: null, // No work id associated
        playbook: {
          playbook_id: playbookId,
          instance_id: instanceId,
          step_id: instance.id,
          previous_step_id: previousInstance?.id,
        },
        applicant_id: AUTOMATION_MANAGER_USER.id, // System user is responsible for the automation
      },
      event: {
        entity_id: instanceId,
        stix: bundle
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
  executor: async ({ instanceId, instance, bundle }) => {
    const created = now();
    const containerType = instance.configuration.container_type;
    if (isStixDomainObjectContainer(containerType)) {
      const baseData = bundle.objects.find((o) => o.id === instanceId) as any;
      const containerData = {
        name: baseData.name ?? `Generated container wrapper from playbook at ${created}`,
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
}
const PLAYBOOK_SHARING_COMPONENT_SCHEMA: JSONSchemaType<SharingConfiguration> = {
  type: 'object',
  properties: {
    organizations: {
      type: 'array',
      uniqueItems: true,
      default: [],
      items: { type: 'string', oneOf: [] }
    }
  },
  required: ['organizations'],
};
const PLAYBOOK_SHARING_COMPONENT: PlaybookComponent<SharingConfiguration> = {
  id: 'PLAYBOOK_SHARING_COMPONENT',
  name: 'Share with organizations',
  description: 'Share the object with organizations within the platform',
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
  executor: async ({ instanceId, instance, bundle }) => {
    const context = executionContext('playbook_components');
    // const organizations = await storeLoadByIds(context, SYSTEM_USER, instance.configuration.organizations, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    const organizations = await getEntitiesListFromCache<BasicStoreEntityOrganization>(context, SYSTEM_USER, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    const organizationIds = organizations
      .filter((o) => (instance.configuration.organizations ?? []).includes(o.internal_id))
      .map((o) => o.standard_id);
    const baseData = bundle.objects.find((o) => o.id === instanceId) as StixCoreObject;
    baseData.extensions[STIX_EXT_OCTI].granted_refs = [...(baseData.extensions[STIX_EXT_OCTI].granted_refs ?? []), ...organizationIds];
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
  actions: { op: 'add' | 'replace' | 'remove', attribute: string, isMultiple: boolean, value: UpdateValueConfiguration[] }[]
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
          isMultiple: { type: 'boolean' },
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
        required: ['op', 'attribute', 'isMultiple', 'value'],
      }
    },
  },
  required: ['actions'],
};
const PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT: PlaybookComponent<UpdateConfiguration> = {
  id: 'PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT',
  name: 'Update knowledge',
  description: 'Manipulate STIX data',
  icon: 'edit',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA,
  schema: async () => PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT_SCHEMA,
  executor: async ({ instanceId, instance, bundle }) => {
    const baseData = bundle.objects.find((o) => o.id === instanceId) as any;
    const { actions } = instance.configuration;
    const patches: Operation[] = actions.map((n) => {
      let path = null;
      if (attributePathMapping[n.attribute]) {
        const { type } = baseData.extensions[STIX_EXT_OCTI];
        if (attributePathMapping[n.attribute][type]) {
          path = attributePathMapping[n.attribute][type];
        } else {
          const key = Object.keys(attributePathMapping[n.attribute]).filter((o) => getParentTypes(type).includes(o)).at(0);
          if (key) {
            path = attributePathMapping[n.attribute][key];
          }
        }
      }
      return { op: n.op, path, value: n.isMultiple ? n.value.map((o) => o.patch_value) : R.head(n.value)?.patch_value };
    }).filter((n) => n.path !== null);
    if (patches.length > 0) {
      jsonpatch.applyPatch(baseData, patches);
    }
    return { output_port: 'out', bundle };
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
  [PLAYBOOK_SHARING_COMPONENT.id]: PLAYBOOK_SHARING_COMPONENT
};

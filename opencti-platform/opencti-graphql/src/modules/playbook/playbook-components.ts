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
import { v4 as uuidv4 } from 'uuid';
import type { PlaybookComponent, PlaybookComponentConfiguration } from './playbook-types';
import { convertFiltersFrontendFormat, isStixMatchFilters } from '../../utils/filtering';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { pushToConnector, pushToSync } from '../../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { loadConnectorById } from '../../domain/connector';
import { convertStoreToStix } from '../../database/stix-converter';
import type { StoreCommon } from '../../types/store';
import { generateStandardId } from '../../schema/identifier';
import { now } from '../../utils/format';
import { STIX_SPEC_VERSION } from '../../database/stix';
import type { StixContainer } from '../../types/stix-sdo';
import { getParentTypes } from '../../schema/schemaUtils';
import { ENTITY_TYPE_CONTAINER_REPORT, isStixDomainObjectContainer } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';

// region Testing playbook components
interface ConsoleConfiguration extends PlaybookComponentConfiguration {}
const PLAYBOOK_CONSOLE_STANDARD_COMPONENT: PlaybookComponent<ConsoleConfiguration> = {
  id: 'PLAYBOOK_CONSOLE_STANDARD_COMPONENT',
  name: 'Standard console',
  description: 'Print data in standard console',
  icon: 'console',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: undefined,
  executor: async ({ bundle }) => {
    // eslint-disable-next-line no-console
    console.log(bundle);
    return { output_port: 'out', bundle };
  }
};
const PLAYBOOK_CONSOLE_ERROR_COMPONENT: PlaybookComponent<ConsoleConfiguration> = {
  id: 'PLAYBOOK_CONSOLE_ERROR_COMPONENT',
  name: 'Error console',
  description: 'Print data in error console',
  icon: 'console',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: undefined,
  executor: async ({ bundle }) => {
    // eslint-disable-next-line no-console
    console.error(bundle);
    return { output_port: 'out', bundle };
  }
};

// region built in playbook components
export interface StreamConfiguration extends PlaybookComponentConfiguration {
  create: boolean,
  update: boolean,
  delete: boolean
}
const PLAYBOOK_INTERNAL_DATA_STREAM: PlaybookComponent<StreamConfiguration> = {
  id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
  name: 'Listen knowledge events',
  description: 'Listen for all platform knowledge events',
  icon: 'stream',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: {
    type: 'object',
    properties: {
      create: { type: 'boolean', default: true },
      update: { type: 'boolean', default: false },
      delete: { type: 'boolean', default: false },
    },
    required: ['create', 'update', 'delete'],
  },
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
  executor: async ({ bundle }) => {
    const content = Buffer.from(JSON.stringify(bundle), 'utf-8').toString('base64');
    await pushToSync({ type: 'bundle', applicant_id: OPENCTI_SYSTEM_UUID, content, update: true });
    return { output_port: undefined, bundle };
  }
};

interface FilterConfiguration extends PlaybookComponentConfiguration {
  filters: string
}
const PLAYBOOK_FILTERING_COMPONENT: PlaybookComponent<FilterConfiguration> = {
  id: 'PLAYBOOK_FILTERING_COMPONENT',
  name: 'Filter knowledge',
  description: 'Filter STIX data',
  icon: 'filter',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'empty', type: 'out' }],
  configuration_schema: {
    type: 'object',
    properties: {
      filters: { type: 'string' },
    },
    required: ['filters'],
  },
  executor: async ({ instance, instanceId, bundle }) => {
    const context = executionContext('playbook_manager');
    const jsonFilters = JSON.parse(instance.configuration.filters);
    const adaptedFilters = await convertFiltersFrontendFormat(context, SYSTEM_USER, jsonFilters);
    const baseData = bundle.objects.find((o) => o.id === instanceId);
    const isMatch = await isStixMatchFilters(context, SYSTEM_USER, baseData, adaptedFilters);
    return { output_port: isMatch ? 'out' : 'empty', bundle };
  }
};

interface ConnectorConfiguration extends PlaybookComponentConfiguration {
  connector_id: string
}
const PLAYBOOK_CONNECTOR_COMPONENT: PlaybookComponent<ConnectorConfiguration> = {
  id: 'PLAYBOOK_CONNECTOR_COMPONENT',
  name: 'Enrich through connector',
  description: 'Use a registered platform connector for enrichment',
  icon: 'enrichment',
  is_entry_point: false,
  is_internal: false,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: {
    type: 'object',
    properties: {
      connector_id: { type: 'string' },
    },
    required: ['connector_id'],
  },
  notify: async ({ playbookId, instance, previousInstance, instanceId, bundle }) => {
    const context = executionContext('playbook_manager');
    const connectorId = instance.configuration.connector_id ?? '00ac0c19-7b1b-457d-a2ff-7a8bda8bfd6f';
    const connector = await loadConnectorById(context, SYSTEM_USER, connectorId);
    const message = {
      internal: {
        work_id: null, // No work id associated
        playbook: {
          playbook_id: playbookId,
          instance_id: instanceId,
          step_id: instance.id,
          previous_step_id: previousInstance?.id,
        },
        applicant_id: SYSTEM_USER.id, // System user is responsible for the automation
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
const PLAYBOOK_CONTAINER_WRAPPER_COMPONENT: PlaybookComponent<ContainerWrapperConfiguration> = {
  id: 'PLAYBOOK_CONTAINER_WRAPPER_COMPONENT',
  name: 'Container wrapper',
  description: 'Create a container and wrap the element inside it',
  icon: 'data',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: {
    type: 'object',
    properties: {
      container_type: {
        type: 'string',
        enum: [ENTITY_TYPE_CONTAINER_CASE_INCIDENT, ENTITY_TYPE_CONTAINER_REPORT],
        default: ENTITY_TYPE_CONTAINER_REPORT
      },
    },
    required: ['container_type'],
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

interface UpdateConfiguration extends PlaybookComponentConfiguration {
  actions: { op: string, path: string, value: string[] }[]
}
const PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT: PlaybookComponent<UpdateConfiguration> = {
  id: 'PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT',
  name: 'Update knowledge',
  description: 'Update STIX data',
  icon: 'edit',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: {
    type: 'object',
    properties: {
      actions: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            op: { type: 'string' },
            path: { type: 'string' },
            value: { type: 'array', items: { type: 'string' } },
          },
          required: ['op', 'path', 'value'],
        }
      },
    },
    required: ['actions'],
  },
  executor: async ({ bundle }) => {
    // const context = executionContext('playbook_manager');
    // const jsonFilters = JSON.parse(instance.configuration.filters);
    // const adaptedFilters = await convertFiltersFrontendFormat(context, SYSTEM_USER, jsonFilters);
    // const isMatch = await isStixMatchFilters(context, SYSTEM_USER, data, adaptedFilters);
    return { output_port: 'out', bundle };
  }
};
// endregion

export const PLAYBOOK_COMPONENTS: { [k: string]: PlaybookComponent<any> } = {
  [PLAYBOOK_INTERNAL_DATA_STREAM.id]: PLAYBOOK_INTERNAL_DATA_STREAM,
  [PLAYBOOK_CONSOLE_STANDARD_COMPONENT.id]: PLAYBOOK_CONSOLE_STANDARD_COMPONENT,
  [PLAYBOOK_CONSOLE_ERROR_COMPONENT.id]: PLAYBOOK_CONSOLE_ERROR_COMPONENT,
  [PLAYBOOK_INGESTION_COMPONENT.id]: PLAYBOOK_INGESTION_COMPONENT,
  [PLAYBOOK_FILTERING_COMPONENT.id]: PLAYBOOK_FILTERING_COMPONENT,
  [PLAYBOOK_CONNECTOR_COMPONENT.id]: PLAYBOOK_CONNECTOR_COMPONENT,
  [PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT.id]: PLAYBOOK_UPDATE_KNOWLEDGE_COMPONENT,
  [PLAYBOOK_CONNECTOR_COMPONENT.id]: PLAYBOOK_CONNECTOR_COMPONENT,
  [PLAYBOOK_CONTAINER_WRAPPER_COMPONENT.id]: PLAYBOOK_CONTAINER_WRAPPER_COMPONENT
};

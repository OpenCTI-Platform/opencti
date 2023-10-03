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

import type { PlaybookComponent, PlaybookComponentConfiguration } from './playbook-types';
import { convertFiltersFrontendFormat, isStixMatchFilters } from '../../utils/filtering';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { pushToConnector, pushToSync } from '../../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';
import { loadConnectorById } from '../../domain/connector';

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
interface StreamConfiguration extends PlaybookComponentConfiguration {}
const PLAYBOOK_INTERNAL_DATA_STREAM: PlaybookComponent<StreamConfiguration> = {
  id: 'PLAYBOOK_INTERNAL_DATA_STREAM',
  name: 'Listen knowledge events',
  description: 'Listen for all platform knowledge events',
  icon: 'stream',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: undefined,
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
// endregion

export const PLAYBOOK_COMPONENTS: { [k: string]: PlaybookComponent<any> } = {
  [PLAYBOOK_INTERNAL_DATA_STREAM.id]: PLAYBOOK_INTERNAL_DATA_STREAM,
  [PLAYBOOK_CONSOLE_STANDARD_COMPONENT.id]: PLAYBOOK_CONSOLE_STANDARD_COMPONENT,
  [PLAYBOOK_CONSOLE_ERROR_COMPONENT.id]: PLAYBOOK_CONSOLE_ERROR_COMPONENT,
  [PLAYBOOK_INGESTION_COMPONENT.id]: PLAYBOOK_INGESTION_COMPONENT,
  [PLAYBOOK_FILTERING_COMPONENT.id]: PLAYBOOK_FILTERING_COMPONENT,
  [PLAYBOOK_CONNECTOR_COMPONENT.id]: PLAYBOOK_CONNECTOR_COMPONENT
};

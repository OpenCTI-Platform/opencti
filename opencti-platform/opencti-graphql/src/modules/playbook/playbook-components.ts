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
import { pushToSync } from '../../database/rabbitmq';
import { OPENCTI_SYSTEM_UUID } from '../../schema/general';

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
  executor: async ({ data }) => {
    // eslint-disable-next-line no-console
    console.log(data);
    return { output_port: 'out', data };
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
  executor: async ({ data }) => {
    // eslint-disable-next-line no-console
    console.error(data);
    return { output_port: 'out', data };
  }
};
/*
interface ConnectorConfiguration extends PlaybookComponentConfiguration {
  connector_id: string
}
const PLAYBOOK_IP_EXTERNAL_CONNECTOR: PlaybookComponent<ConnectorConfiguration> = {
  id: 'PLAYBOOK_IP_EXTERNAL_CONNECTOR',
  name: 'External ip enrichment',
  description: 'IP enrichment connector',
  is_entry_point: false,
  is_internal: false,
  ports: [{ id: 'enriched', type: 'out' }, { id: 'untouched', type: 'out' }],
  configuration_schema: {
    type: 'object',
    properties: {
      connector_id: { type: 'string' },
    },
    required: ['connector_id'],
  },
  executor: async ({ playbookRunId, instance, data }) => {
    const context = executionContext('playbook_manager');
    const connector = await loadConnectorById(context, SYSTEM_USER, instance.configuration.connector_id);
    await pushToConnector(context, connector, { execution_id: playbookRunId, data });
    // In this mode is not possible to chain execution
    // The chain will be ensure outside the manager (router api)
    return { output_port: undefined, data };
  }
};
*/
// endregion

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
  executor: async ({ data }) => {
    return ({ output_port: 'out', data });
  }
};

interface IngestionConfiguration extends PlaybookComponentConfiguration {}
const PLAYBOOK_INGESTION_COMPONENT: PlaybookComponent<IngestionConfiguration> = {
  id: 'PLAYBOOK_WRITE_COMPONENT',
  name: 'Send to absorption',
  description: 'Send stix data to get injected',
  icon: 'storage',
  is_entry_point: false,
  is_internal: true,
  ports: [],
  configuration_schema: undefined,
  executor: async ({ data }) => {
    const bundle = { type: 'bundle', id: `bundle--${uuidv4()}`, objects: [data] };
    const stixBundle = JSON.stringify(bundle);
    const content = Buffer.from(stixBundle, 'utf-8').toString('base64');
    await pushToSync({ type: 'bundle', applicant_id: OPENCTI_SYSTEM_UUID, content, update: true });
    return { output_port: undefined, data };
  }
};

interface FilterConfiguration extends PlaybookComponentConfiguration {
  filters: string
}
const PLAYBOOK_FILTERING_COMPONENT: PlaybookComponent<FilterConfiguration> = {
  id: 'PLAYBOOK_FILTERING_COMPONENT',
  name: 'Filter knowledge',
  description: 'Filter stix data',
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
  executor: async ({ instance, data }) => {
    const context = executionContext('playbook_manager');
    const jsonFilters = JSON.parse(instance.configuration.filters);
    const adaptedFilters = await convertFiltersFrontendFormat(context, SYSTEM_USER, jsonFilters);
    const isMatch = await isStixMatchFilters(context, SYSTEM_USER, data, adaptedFilters);
    return { output_port: isMatch ? 'out' : 'empty', data };
  }
};
// endregion

export const PLAYBOOK_COMPONENTS: { [k: string]: PlaybookComponent<StreamConfiguration> } = {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  // PLAYBOOK_IP_EXTERNAL_CONNECTOR,
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  PLAYBOOK_FILTERING_COMPONENT,
  PLAYBOOK_INTERNAL_DATA_STREAM,
  PLAYBOOK_CONSOLE_STANDARD_COMPONENT,
  PLAYBOOK_CONSOLE_ERROR_COMPONENT,
  PLAYBOOK_INGESTION_COMPONENT
};

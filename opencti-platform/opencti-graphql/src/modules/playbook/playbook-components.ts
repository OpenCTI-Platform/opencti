import type { PlaybookComponent, PlaybookComponentConfiguration } from './playbook-types';
import { convertFiltersFrontendFormat, isStixMatchFilters } from '../../utils/filtering';
import { executionContext, SYSTEM_USER } from '../../utils/access';

// region Testing playbook components
interface ConsoleConfiguration extends PlaybookComponentConfiguration {}
const PLAYBOOK_CONSOLE_STANDARD_COMPONENT: PlaybookComponent<ConsoleConfiguration> = {
  id: 'PLAYBOOK_CONSOLE_STANDARD_COMPONENT',
  name: 'Standard console',
  description: 'Print data in standard console',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: undefined,
  executor: async ({ data }) => {
    // eslint-disable-next-line no-console
    console.log(data);
    return { output_port: undefined, data };
  }
};
const PLAYBOOK_CONSOLE_ERROR_COMPONENT: PlaybookComponent<ConsoleConfiguration> = {
  id: 'PLAYBOOK_CONSOLE_ERROR_COMPONENT',
  name: 'Error console',
  description: 'Print data in error console',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: undefined,
  executor: async ({ data }) => {
    // eslint-disable-next-line no-console
    console.error(data);
    return { output_port: undefined, data };
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
  name: 'Internal stream listener',
  description: 'Listen platform data events',
  is_entry_point: true,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }],
  configuration_schema: undefined,
  executor: async ({ data }) => {
    return ({ output_port: 'out', data });
  }
};

interface FilterConfiguration extends PlaybookComponentConfiguration {
  filters: string
}
const PLAYBOOK_FILTERING_COMPONENT: PlaybookComponent<FilterConfiguration> = {
  id: 'PLAYBOOK_FILTERING_COMPONENT',
  name: 'Stix filtering component',
  description: 'Filter stix data',
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
  PLAYBOOK_CONSOLE_ERROR_COMPONENT
};

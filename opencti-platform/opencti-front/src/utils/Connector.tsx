import { ConnectorsStateQuery$data } from '@components/data/connectors/__generated__/ConnectorsStateQuery.graphql';
import { stixFilters, useAvailableFilterKeysForEntityTypes } from './filters/filtersUtils';
import useSchema from './hooks/useSchema';

export interface Connector {
  name: string;
  active: boolean;
  auto: boolean ;
  only_contextual: boolean;
  connector_trigger_filters: string;
  connector_type: string;
  connector_scope: ReadonlyArray<string>;
  connector_state: string;
}

interface ConnectorStatus {
  status: boolean | null;
  label: string;
}

export const connectorsWithTrigger = ['INTERNAL_ENRICHMENT', 'INTERNAL_IMPORT_FILE'];

export const CONNECTOR_STATUS_NOT_APPLICABLE = 'Not applicable';
export const CONNECTOR_TRIGGER_AUTO = 'Automatic';
export const CONNECTOR_TRIGGER_MANUAL = 'Manual';

export const getConnectorTriggerStatus = (connector: Connector): ConnectorStatus => {
  if (!connector.connector_type || !connectorsWithTrigger.includes(connector.connector_type)) {
    return { status: null, label: CONNECTOR_STATUS_NOT_APPLICABLE };
  }
  if (connector.auto || connector.connector_trigger_filters) { // automatic is either auto or trigger with filters
    return { status: true, label: CONNECTOR_TRIGGER_AUTO };
  }
  return { status: false, label: CONNECTOR_TRIGGER_MANUAL };
};

export const getConnectorOnlyContextualStatus = (connector: Connector): ConnectorStatus => {
  if (!connector.connector_type || !connectorsWithTrigger.includes(connector.connector_type)) {
    return { status: null, label: CONNECTOR_STATUS_NOT_APPLICABLE };
  }
  if (connector.only_contextual) {
    return { status: connector.auto ?? false, label: 'Yes' };
  }
  return { status: connector.auto ?? false, label: 'No' };
};

export const useGetConnectorFilterEntityTypes = (connector: Connector): string[] => {
  const { allEntityTypes } = useSchema();
  // keep the scopes that are entity types (remove scope like 'text/csv')
  const entityTypesScopes = (connector.connector_scope ?? []).filter((scope) => allEntityTypes.includes(scope));
  // return the entity types scopes
  return entityTypesScopes.length > 0 ? [...entityTypesScopes] : ['Stix-Core-Object', 'Stix-Filtering'];
};

export const useGetConnectorAvailableFilterKeys = (connector: Connector): string[] => {
  if (connector.connector_type !== 'INTERNAL_ENRICHMENT') {
    return []; // only for enrichment
  }
  const entityTypes = useGetConnectorFilterEntityTypes(connector);
  let availableFilterKeys = useAvailableFilterKeysForEntityTypes(entityTypes);
  // filter to keep only stixFilters
  availableFilterKeys = availableFilterKeys.filter((key) => stixFilters.includes(key));
  return availableFilterKeys;
};

export const computeConnectorStatus = ({
  manager_current_status,
  manager_requested_status,
  active,
}: Partial<ConnectorsStateQuery$data['connectors'][0]>) => {
  if (manager_requested_status) {
    // On connector created, manager_current_status is null
    const isTransitioning = (manager_current_status ?? '').slice(0, 5) !== manager_requested_status.slice(0, 5);

    if (isTransitioning) {
      const isProcessing = ['starting', 'stopping'].includes(manager_requested_status);

      if (isProcessing) {
        return {
          status: 'processing',
          processing: true,
          label: manager_requested_status,
        };
      }

      if (manager_requested_status === 'stopped') {
        return {
          status: 'stopped',
          processing: false,
          label: manager_requested_status,
        };
      }

      return {
        status: 'active',
        processing: false,
        label: manager_requested_status,
      };
    }

    const isStarted = manager_current_status === 'started';
    return {
      status: isStarted ? 'active' : 'inactive',
      processing: false,
      label: manager_current_status || '',
    };
  }

  // No manager status - use regular active/inactive
  return {
    status: active ? 'active' : 'inactive',
    processing: false,
    label: active ? 'Active' : 'Inactive',
  };
};

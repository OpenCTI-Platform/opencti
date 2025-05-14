import { uniq } from 'ramda';
import { stixFilters, useBuildFilterKeysMapFromEntityType } from './filters/filtersUtils';
import useSchema from './hooks/useSchema';

export interface Connector {
  name: string;
  active: boolean;
  auto: boolean;
  only_contextual: boolean;
  connector_trigger_filters: string;
  connector_type: string;
  connector_scope: string[];
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
  if (!connectorsWithTrigger.includes(connector.connector_type)) {
    return { status: null, label: CONNECTOR_STATUS_NOT_APPLICABLE };
  }
  if (connector.auto || connector.connector_trigger_filters) { // automatic is either auto or trigger with filters
    return { status: true, label: CONNECTOR_TRIGGER_AUTO };
  }
  return { status: false, label: CONNECTOR_TRIGGER_MANUAL };
};

export const getConnectorOnlyContextualStatus = (connector: Connector): ConnectorStatus => {
  if (!connectorsWithTrigger.includes(connector.connector_type)) {
    return { status: null, label: CONNECTOR_STATUS_NOT_APPLICABLE };
  }
  if (connector.only_contextual) {
    return { status: connector.auto, label: 'Yes' };
  }
  return { status: connector.auto, label: 'No' };
};

export const useGetConnectorFilterEntityTypes = (connector: Connector): string[] => {
  const { allEntityTypes } = useSchema();
  // keep the scopes that are entity types (remove scope like 'text/csv')
  const entityTypesScopes = connector.connector_scope.filter((scope) => allEntityTypes.includes(scope));
  // return the entity types scopes
  return entityTypesScopes.length > 0 ? [...entityTypesScopes] : ['Stix-Core-Object', 'Stix-Filtering'];
};

export const useGetConnectorAvailableFilterKeys = (connector: Connector): string[] => {
  if (connector.connector_type !== 'INTERNAL_ENRICHMENT') {
    return []; // only for enrichment
  }
  const entityTypes = useGetConnectorFilterEntityTypes(connector);
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  let availableFilterKeys = uniq(Array.from(filterKeysMap.keys() ?? []));
  // filter to keep only stixFilters
  availableFilterKeys = availableFilterKeys.filter((key) => stixFilters.includes(key));
  return availableFilterKeys;
};

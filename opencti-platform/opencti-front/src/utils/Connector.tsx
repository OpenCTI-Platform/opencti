import { ConnectorsStateQuery$data } from '@components/data/connectors/__generated__/ConnectorsStateQuery.graphql';
import { useAvailableFilterKeysForEntityTypes, useStixFilters } from './filters/filtersUtils';
import useSchema from './hooks/useSchema';

export interface Connector {
  name: string;
  active: boolean;
  auto: boolean;
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
  // filter to keep only stixFilters
  const entityTypes = useGetConnectorFilterEntityTypes(connector);
  let availableFilterKeys = useAvailableFilterKeysForEntityTypes(entityTypes);
  const stixFilters = useStixFilters();
  availableFilterKeys = availableFilterKeys.filter((key) => stixFilters.includes(key));
  return availableFilterKeys;
};

// Only the fields the status reads: a connector of any query carrying them fits, whatever its other fragments
export type ConnectorStatusSource = Partial<Pick<ConnectorsStateQuery$data['connectors'][0], 'manager_current_status' | 'manager_requested_status' | 'active'>>;

// Reduced status of an integration (connector, feed...): decides the color of its status chip and the status facet
export type IntegrationStatus = 'active' | 'inactive' | 'processing';

// Without the ingestion health feature: inactive when the connector is not started (managed), or when it has no heartbeat (the others)
const computeLegacyIntegrationStatus = ({
  manager_current_status,
  manager_requested_status,
  active,
}: ConnectorStatusSource): IntegrationStatus => {
  if (manager_requested_status) {
    // On connector created, manager_current_status is null
    const isTransitioning = (manager_current_status ?? '').slice(0, 5) !== manager_requested_status.slice(0, 5);
    if (isTransitioning) {
      if (['starting', 'stopping'].includes(manager_requested_status)) return 'processing';
      return manager_requested_status === 'stopped' ? 'inactive' : 'active';
    }
    return manager_current_status === 'started' ? 'active' : 'inactive';
  }
  return active ? 'active' : 'inactive';
};

// With the ingestion health feature: inactive only when stopped on purpose: only a managed connector can be (see isConnectorStopped in the backend).
// Any other connector is active: a missing heartbeat is a failure reported by its health, not a stop
const computeIntegrationStatusWithHealth = ({
  manager_current_status,
  manager_requested_status,
}: ConnectorStatusSource): IntegrationStatus => {
  let integrationStatus: IntegrationStatus = 'active';
  if (manager_requested_status) {
    // On connector created, manager_current_status is null
    const isTransitioning = (manager_current_status ?? '').slice(0, 5) !== manager_requested_status.slice(0, 5);
    if (isTransitioning) {
      if (['starting', 'stopping'].includes(manager_requested_status)) integrationStatus = 'processing';
      else if (manager_requested_status === 'stopped') integrationStatus = 'inactive';
    } else if (manager_current_status === 'stopped') {
      integrationStatus = 'inactive';
    }
  }
  return integrationStatus;
};

// The ingestion health feature changes the rule: see computeIntegrationStatusWithHealth
export const computeConnectorStatus = (connector: ConnectorStatusSource, isIngestionHealthEnabled: boolean) => {
  const integrationStatus = isIngestionHealthEnabled ? computeIntegrationStatusWithHealth(connector) : computeLegacyIntegrationStatus(connector);
  return { integrationStatus, processing: integrationStatus === 'processing' };
};

import { uniq } from 'ramda';
import React from 'react';
import { ConnectorsStatus_data$data } from '@components/data/connectors/__generated__/ConnectorsStatus_data.graphql';
import { stixFilters, useBuildFilterKeysMapFromEntityType } from './filters/filtersUtils';
import ItemBoolean from '../components/ItemBoolean';
import { useFormatter } from '../components/i18n';

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

export const getConnectorFilterEntityTypes = (connector: Connector): string[] => {
  return connector.connector_scope.length > 0 ? [...connector.connector_scope] : ['Stix-Core-Object', 'Stix-Filtering'];
};

export const getConnectorAvailableFilterKeys = (connector: Connector): string[] => {
  if (connector.connector_type !== 'INTERNAL_ENRICHMENT') {
    return []; // only for enrichment
  }
  const entityTypes = getConnectorFilterEntityTypes(connector);
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  let availableFilterKeys = uniq(Array.from(filterKeysMap.keys() ?? []));
  // filter to keep only stixFilters
  availableFilterKeys = availableFilterKeys.filter((key) => stixFilters.includes(key));
  return availableFilterKeys;
};

export const useComputeConnectorStatus = () => {
  const { t_i18n } = useFormatter();
  // eslint-disable-next-line react/display-name
  return ({
    manager_current_status,
    manager_requested_status,
    active,
  }: Partial<ConnectorsStatus_data$data['connectors'][0]>) => {
    if (manager_current_status && manager_requested_status) {
      if (manager_current_status.slice(0, 5) !== manager_requested_status.slice(0, 5)) {
        return (
          <ItemBoolean
            status={['starting', 'stopping'].includes(manager_requested_status) ? undefined : true}
            label={t_i18n(manager_requested_status)}
            variant="inList"
          />
        );
      }
      return (
        <ItemBoolean
          status={manager_current_status === 'started'}
          label={t_i18n(manager_current_status)}
          variant="inList"
        />
      );
    }
    return (
      <ItemBoolean
        status={active}
        label={active ? t_i18n('Active') : t_i18n('Inactive')}
        variant="inList"
      />
    );
  };
};

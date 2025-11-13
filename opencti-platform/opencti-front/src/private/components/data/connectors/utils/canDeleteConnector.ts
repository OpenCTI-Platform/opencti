import { Connector_connector$data } from '@components/data/connectors/__generated__/Connector_connector.graphql';

/**
 * Determines if a connector can be deleted based on its state.
 *
 * @param connector - The connector to check
 * @returns true if the connector can be deleted, false otherwise
 */
const canDeleteConnector = (connector: Connector_connector$data): boolean => {
  // Built-in connectors cannot be deleted
  if (connector.built_in) {
    return false;
  }

  // For managed connectors, allow deletion only after stop has been requested or connector is stopped
  if (connector.is_managed) {
    return connector.manager_requested_status === 'stopping'
      || connector.manager_requested_status === 'stopped'
      || connector.manager_current_status === 'stopped';
  }

  // For non-managed connectors, cannot delete if active
  return !connector.active;
};

export default canDeleteConnector;

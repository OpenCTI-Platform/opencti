// A connector without a heartbeat for this long is inactive (isConnectorActive) and,
// when it pings every 40 seconds, lost for the ingestion health (NO_HEARTBEAT)
export const CONNECTOR_HEARTBEAT_TIMEOUT_SECONDS = 300;

// Fields read by the managed connector stop rules
export interface ManagedConnectorStatusFields {
  is_managed?: boolean | null;
  catalog_id?: string | null;
  manager_requested_status?: string | null;
  manager_current_status?: string | null;
}

// Same as is_managed || isNotEmptyField(catalog_id), without the import: catalog_id is a string,
// and an empty string is empty for isNotEmptyField (ramda isEmpty)
const isManagedConnector = (connector: ManagedConnectorStatusFields): boolean => {
  return Boolean(connector.is_managed) || (connector.catalog_id !== undefined && connector.catalog_id !== null && connector.catalog_id !== '');
};

// A person asked the managed connector to stop: only the requested status is a person's decision.
// Ingestion health uses this rule alone: xtm-composer reports the current status 'stopped' for any container
// that is not running (crashed, exited, restarting) while the requested status stays 'starting',
// and a crash must not be painted as a person's decision. It goes through the heartbeat check.
export const isStopRequestedByUser = (connector: ManagedConnectorStatusFields): boolean => {
  return isManagedConnector(connector)
    && (connector.manager_requested_status === 'stopping' || connector.manager_requested_status === 'stopped');
};

// A managed connector that is stopped, asked to or reported so by the composer: the rule of isConnectorActive,
// which also counts the current status because an inactive connector is inactive, whatever the cause
export const isManagedConnectorStopped = (connector: ManagedConnectorStatusFields): boolean => {
  return isStopRequestedByUser(connector)
    || (isManagedConnector(connector) && connector.manager_current_status === 'stopped');
};

// A connector without a heartbeat for this long is inactive (isConnectorActive) and,
// when it pings every 40 seconds, lost for the ingestion health (NO_HEARTBEAT)
export const CONNECTOR_HEARTBEAT_TIMEOUT_SECONDS = 300;

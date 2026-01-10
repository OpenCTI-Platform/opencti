package io.filigran.opencti.api;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

/**
 * API module for managing OpenCTI connectors.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
@RequiredArgsConstructor
public class OpenCTIApiConnector {

    private final OpenCTIApiClient client;

    private static final String CONNECTOR_PROPERTIES = """
        id
        name
        active
        auto
        only_contextual
        connector_type
        connector_scope
        connector_state
        updated_at
        created_at
        """;

    /**
     * List all connectors.
     *
     * @return list of connectors
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> list() {
        log.info("Listing connectors");
        
        String query = """
            query Connectors {
                connectors {
                    """ + CONNECTOR_PROPERTIES + """
                }
            }
            """;
        
        Map<String, Object> result = client.query(query);
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return (List<Map<String, Object>>) data.get("connectors");
    }

    /**
     * Read a connector by ID.
     *
     * @param connectorId the connector ID
     * @return the connector data
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> read(String connectorId) {
        log.info("Reading connector: {}", connectorId);
        
        String query = """
            query Connector($id: String!) {
                connector(id: $id) {
                    """ + CONNECTOR_PROPERTIES + """
                }
            }
            """;
        
        Map<String, Object> result = client.query(query, Map.of("id", connectorId));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return (Map<String, Object>) data.get("connector");
    }

    /**
     * Register a connector.
     *
     * @param connectorId the connector ID
     * @param connectorName the connector name
     * @param connectorType the connector type
     * @param connectorScope the connector scope
     * @param auto whether auto is enabled
     * @param onlyContextual whether only contextual mode is enabled
     * @return the registered connector data
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> register(
            String connectorId,
            String connectorName,
            String connectorType,
            List<String> connectorScope,
            boolean auto,
            boolean onlyContextual) {
        
        log.info("Registering connector: {} ({})", connectorName, connectorId);
        
        String mutation = """
            mutation RegisterConnector($input: RegisterConnectorInput!) {
                registerConnector(input: $input) {
                    """ + CONNECTOR_PROPERTIES + """
                }
            }
            """;
        
        Map<String, Object> input = Map.of(
            "id", connectorId,
            "name", connectorName,
            "type", connectorType,
            "scope", connectorScope,
            "auto", auto,
            "only_contextual", onlyContextual
        );
        
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return (Map<String, Object>) data.get("registerConnector");
    }

    /**
     * Ping a connector to update its last seen timestamp.
     *
     * @param connectorId the connector ID
     * @param connectorState the connector state
     * @return the updated connector data
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> ping(String connectorId, String connectorState) {
        log.debug("Pinging connector: {}", connectorId);
        
        String mutation = """
            mutation PingConnector($id: ID!, $state: String) {
                pingConnector(id: $id, state: $state) {
                    """ + CONNECTOR_PROPERTIES + """
                }
            }
            """;
        
        Map<String, Object> result = client.query(mutation, Map.of(
            "id", connectorId,
            "state", connectorState != null ? connectorState : ""
        ));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return (Map<String, Object>) data.get("pingConnector");
    }

    /**
     * Reset the state of a connector.
     *
     * @param connectorId the connector ID
     */
    public void resetState(String connectorId) {
        log.info("Resetting connector state: {}", connectorId);
        
        String mutation = """
            mutation ResetConnectorState($id: ID!) {
                resetStateConnector(id: $id) {
                    id
                }
            }
            """;
        
        client.query(mutation, Map.of("id", connectorId));
    }

    /**
     * Delete a connector.
     *
     * @param connectorId the connector ID
     */
    public void delete(String connectorId) {
        log.info("Deleting connector: {}", connectorId);
        
        String mutation = """
            mutation DeleteConnector($id: ID!) {
                deleteConnector(id: $id)
            }
            """;
        
        client.query(mutation, Map.of("id", connectorId));
    }
}


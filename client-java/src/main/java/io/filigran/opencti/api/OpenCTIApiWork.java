package io.filigran.opencti.api;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

/**
 * API module for managing OpenCTI work operations.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
@RequiredArgsConstructor
public class OpenCTIApiWork {

    private final OpenCTIApiClient client;

    /**
     * Initiate a new work for a connector.
     *
     * @param connectorId the connector ID
     * @param friendlyName a friendly name for the work
     * @return the work ID
     */
    @SuppressWarnings("unchecked")
    public String initiateWork(String connectorId, String friendlyName) {
        log.info("Initiating work for connector: {}", connectorId);
        
        String mutation = """
            mutation WorkAdd($connectorId: String!, $friendlyName: String) {
                workAdd(connectorId: $connectorId, friendlyName: $friendlyName) {
                    id
                }
            }
            """;
        
        Map<String, Object> result = client.query(mutation, Map.of(
            "connectorId", connectorId,
            "friendlyName", friendlyName
        ));
        
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        Map<String, Object> workAdd = (Map<String, Object>) data.get("workAdd");
        return (String) workAdd.get("id");
    }

    /**
     * Update the processing count of a work.
     *
     * @param workId the work ID
     * @param processingCount the new processing count
     */
    public void updateProcessingCount(String workId, int processingCount) {
        log.info("Updating processing count for work: {} to {}", workId, processingCount);
        
        String mutation = """
            mutation WorkEdit($id: ID!, $input: [EditInput!]!) {
                workEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                    }
                }
            }
            """;
        
        client.query(mutation, Map.of(
            "id", workId,
            "input", List.of(Map.of(
                "key", "import_expected_number",
                "value", String.valueOf(processingCount)
            ))
        ));
    }

    /**
     * Report an error for a work.
     *
     * @param workId the work ID
     * @param errorMessage the error message
     * @param sourceId optional source ID
     */
    public void reportError(String workId, String errorMessage, String sourceId) {
        log.info("Reporting error for work: {}", workId);
        
        String mutation = """
            mutation WorkAddExpectation($id: ID!, $input: WorkToProcessInput!) {
                workEdit(id: $id) {
                    addExpectation(input: $input) {
                        id
                    }
                }
            }
            """;
        
        Map<String, Object> input = new java.util.HashMap<>();
        input.put("type", "Error");
        input.put("message", errorMessage);
        if (sourceId != null) {
            input.put("source_id", sourceId);
        }
        
        client.query(mutation, Map.of("id", workId, "input", input));
    }

    /**
     * Complete a work.
     *
     * @param workId the work ID
     * @param message completion message
     * @param inError whether the work completed in error
     */
    public void complete(String workId, String message, boolean inError) {
        log.info("Completing work: {} (inError: {})", workId, inError);
        
        String mutation = """
            mutation WorkEdit($id: ID!, $message: String, $inError: Boolean) {
                workEdit(id: $id) {
                    toProcessed(message: $message, inError: $inError)
                }
            }
            """;
        
        client.query(mutation, Map.of(
            "id", workId,
            "message", message,
            "inError", inError
        ));
    }

    /**
     * Delete a work.
     *
     * @param workId the work ID
     */
    public void delete(String workId) {
        log.info("Deleting work: {}", workId);
        
        String mutation = """
            mutation WorkDelete($id: ID!) {
                workDelete(id: $id)
            }
            """;
        
        client.query(mutation, Map.of("id", workId));
    }
}


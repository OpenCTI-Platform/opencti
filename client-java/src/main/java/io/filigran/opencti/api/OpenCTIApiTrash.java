package io.filigran.opencti.api;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

/**
 * API module for managing OpenCTI trash operations.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
@RequiredArgsConstructor
public class OpenCTIApiTrash {

    private final OpenCTIApiClient client;

    /**
     * List deleted elements.
     *
     * @param first the number of elements to retrieve
     * @param after the cursor for pagination
     * @return list of deleted elements
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> list(int first, String after) {
        log.info("Listing deleted elements");
        
        String query = """
            query DeletedElements($first: Int, $after: ID) {
                deletedElements(first: $first, after: $after) {
                    edges {
                        node {
                            id
                            entity_type
                            standard_id
                            name
                            deletor {
                                id
                                name
                            }
                        }
                    }
                    pageInfo {
                        startCursor
                        endCursor
                        hasNextPage
                        hasPreviousPage
                        globalCount
                    }
                }
            }
            """;
        
        Map<String, Object> variables = new java.util.HashMap<>();
        variables.put("first", first);
        if (after != null) {
            variables.put("after", after);
        }
        
        Map<String, Object> result = client.query(query, variables);
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        Map<String, Object> deletedElements = (Map<String, Object>) data.get("deletedElements");
        return client.processMultiple(deletedElements);
    }

    /**
     * Restore an element from trash.
     *
     * @param id the element ID to restore
     */
    public void restore(String id) {
        log.info("Restoring element: {}", id);
        
        String mutation = """
            mutation RestoreElement($id: ID!) {
                stixCoreObjectEdit(id: $id) {
                    restore
                }
            }
            """;
        
        client.query(mutation, Map.of("id", id));
    }

    /**
     * Permanently delete an element.
     *
     * @param id the element ID to permanently delete
     */
    public void permanentDelete(String id) {
        log.info("Permanently deleting element: {}", id);
        
        String mutation = """
            mutation PermanentDelete($id: ID!) {
                deleteElementPermanently(id: $id)
            }
            """;
        
        client.query(mutation, Map.of("id", id));
    }
}


package io.filigran.opencti.api;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

/**
 * API module for managing OpenCTI draft workspaces.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
@RequiredArgsConstructor
public class OpenCTIApiDraft {

    private final OpenCTIApiClient client;

    /**
     * Create a new draft workspace.
     *
     * @param name the name of the draft
     * @param entityId optional entity ID to associate with the draft
     * @return the draft workspace ID
     */
    @SuppressWarnings("unchecked")
    public String create(String name, String entityId) {
        log.info("Creating draft: {}", name);
        
        String mutation = """
            mutation DraftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
                draftWorkspaceAdd(input: $input) {
                    id
                }
            }
            """;
        
        Map<String, Object> input = new java.util.HashMap<>();
        input.put("name", name);
        if (entityId != null) {
            input.put("entity_id", entityId);
        }
        
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        Map<String, Object> draftWorkspaceAdd = (Map<String, Object>) data.get("draftWorkspaceAdd");
        return (String) draftWorkspaceAdd.get("id");
    }

    /**
     * Read a draft workspace.
     *
     * @param draftId the draft ID
     * @return the draft workspace data
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> read(String draftId) {
        log.info("Reading draft: {}", draftId);
        
        String query = """
            query DraftWorkspace($id: String!) {
                draftWorkspace(id: $id) {
                    id
                    name
                    created_at
                    updated_at
                    entity_id
                }
            }
            """;
        
        Map<String, Object> result = client.query(query, Map.of("id", draftId));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return (Map<String, Object>) data.get("draftWorkspace");
    }

    /**
     * List all draft workspaces.
     *
     * @return list of draft workspaces
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> list() {
        log.info("Listing drafts");
        
        String query = """
            query DraftWorkspaces {
                draftWorkspaces {
                    edges {
                        node {
                            id
                            name
                            created_at
                            updated_at
                            entity_id
                        }
                    }
                }
            }
            """;
        
        Map<String, Object> result = client.query(query);
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        Map<String, Object> draftWorkspaces = (Map<String, Object>) data.get("draftWorkspaces");
        return client.processMultiple(draftWorkspaces);
    }

    /**
     * Validate and approve a draft workspace.
     *
     * @param draftId the draft ID
     */
    public void validate(String draftId) {
        log.info("Validating draft: {}", draftId);
        
        String mutation = """
            mutation DraftWorkspaceValidate($id: ID!) {
                draftWorkspaceValidate(id: $id)
            }
            """;
        
        client.query(mutation, Map.of("id", draftId));
    }

    /**
     * Delete a draft workspace.
     *
     * @param draftId the draft ID
     */
    public void delete(String draftId) {
        log.info("Deleting draft: {}", draftId);
        
        String mutation = """
            mutation DraftWorkspaceDelete($id: ID!) {
                draftWorkspaceDelete(id: $id)
            }
            """;
        
        client.query(mutation, Map.of("id", draftId));
    }
}


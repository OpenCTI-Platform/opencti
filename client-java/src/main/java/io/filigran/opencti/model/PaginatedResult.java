package io.filigran.opencti.model;

import lombok.Data;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Represents a paginated result from the OpenCTI API.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Data
public class PaginatedResult {
    
    /**
     * The list of entities in this page.
     */
    private List<Map<String, Object>> entities = new ArrayList<>();
    
    /**
     * Pagination information including cursors and counts.
     */
    private Map<String, Object> pagination;
    
    /**
     * Get the start cursor for the current page.
     *
     * @return the start cursor, or null if not available
     */
    public String getStartCursor() {
        if (pagination != null && pagination.containsKey("startCursor")) {
            return (String) pagination.get("startCursor");
        }
        return null;
    }
    
    /**
     * Get the end cursor for the current page.
     *
     * @return the end cursor, or null if not available
     */
    public String getEndCursor() {
        if (pagination != null && pagination.containsKey("endCursor")) {
            return (String) pagination.get("endCursor");
        }
        return null;
    }
    
    /**
     * Check if there is a next page.
     *
     * @return true if there is a next page
     */
    public boolean hasNextPage() {
        if (pagination != null && pagination.containsKey("hasNextPage")) {
            return Boolean.TRUE.equals(pagination.get("hasNextPage"));
        }
        return false;
    }
    
    /**
     * Check if there is a previous page.
     *
     * @return true if there is a previous page
     */
    public boolean hasPreviousPage() {
        if (pagination != null && pagination.containsKey("hasPreviousPage")) {
            return Boolean.TRUE.equals(pagination.get("hasPreviousPage"));
        }
        return false;
    }
    
    /**
     * Get the global count of all entities.
     *
     * @return the global count, or -1 if not available
     */
    public int getGlobalCount() {
        if (pagination != null && pagination.containsKey("globalCount")) {
            Object count = pagination.get("globalCount");
            if (count instanceof Number) {
                return ((Number) count).intValue();
            }
        }
        return -1;
    }
}


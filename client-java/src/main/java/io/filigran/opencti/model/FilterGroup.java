package io.filigran.opencti.model;

import lombok.Builder;
import lombok.Data;
import java.util.List;

/**
 * Represents a filter group for OpenCTI queries.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Data
@Builder
public class FilterGroup {
    
    /**
     * The filter mode (and/or).
     */
    @Builder.Default
    private String mode = "and";
    
    /**
     * The list of filters.
     */
    private List<Filter> filters;
    
    /**
     * Nested filter groups.
     */
    private List<FilterGroup> filterGroups;
    
    /**
     * Represents a single filter.
     */
    @Data
    @Builder
    public static class Filter {
        /**
         * The field key to filter on.
         */
        private String key;
        
        /**
         * The values to filter for.
         */
        private List<String> values;
        
        /**
         * The filter operator (eq, not_eq, contains, etc.).
         */
        @Builder.Default
        private String operator = "eq";
        
        /**
         * The filter mode (and/or) for multiple values.
         */
        @Builder.Default
        private String mode = "or";
    }
    
    /**
     * Create a simple equals filter.
     *
     * @param key the field key
     * @param values the values to filter for
     * @return a new FilterGroup
     */
    public static FilterGroup eq(String key, String... values) {
        return FilterGroup.builder()
            .mode("and")
            .filters(List.of(
                Filter.builder()
                    .key(key)
                    .values(List.of(values))
                    .operator("eq")
                    .build()
            ))
            .filterGroups(List.of())
            .build();
    }
    
    /**
     * Create a contains filter.
     *
     * @param key the field key
     * @param value the value to search for
     * @return a new FilterGroup
     */
    public static FilterGroup contains(String key, String value) {
        return FilterGroup.builder()
            .mode("and")
            .filters(List.of(
                Filter.builder()
                    .key(key)
                    .values(List.of(value))
                    .operator("contains")
                    .build()
            ))
            .filterGroups(List.of())
            .build();
    }
}


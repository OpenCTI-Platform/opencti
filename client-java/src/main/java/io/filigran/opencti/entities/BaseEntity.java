package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import io.filigran.opencti.model.FilterGroup;
import io.filigran.opencti.model.PaginatedResult;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Base class for all OpenCTI entity handlers.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
@RequiredArgsConstructor
public abstract class BaseEntity {

    @Getter
    protected final OpenCTIApiClient client;

    /**
     * Get the entity type name (e.g., "Malware", "Indicator").
     */
    protected abstract String getEntityType();

    /**
     * Get the singular entity name for queries (e.g., "malware", "indicator").
     */
    protected abstract String getEntityName();

    /**
     * Get the plural entity name for queries (e.g., "malwares", "indicators").
     */
    protected abstract String getEntityNamePlural();

    /**
     * Get the default properties to query.
     */
    protected abstract String getProperties();

    /**
     * Get the properties including files.
     */
    protected String getPropertiesWithFiles() {
        return getProperties();
    }

    /**
     * Get the ordering enum name for this entity.
     */
    protected abstract String getOrderingEnum();

    /**
     * List entities with the given parameters.
     *
     * @param filters the filters to apply
     * @param search the search keyword
     * @param first the number of results to return
     * @param after the cursor for pagination
     * @param orderBy the field to order by
     * @param orderMode the ordering mode (asc/desc)
     * @return list of entities
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> list(
            FilterGroup filters,
            String search,
            Integer first,
            String after,
            String orderBy,
            String orderMode) {
        
        return list(filters, search, first, after, orderBy, orderMode, false, false, null).getEntities();
    }

    /**
     * List entities with full control over parameters.
     *
     * @param filters the filters to apply
     * @param search the search keyword
     * @param first the number of results to return
     * @param after the cursor for pagination
     * @param orderBy the field to order by
     * @param orderMode the ordering mode (asc/desc)
     * @param withPagination whether to include pagination info
     * @param withFiles whether to include files in response
     * @param customAttributes custom attributes to return
     * @return paginated result
     */
    @SuppressWarnings("unchecked")
    public PaginatedResult list(
            FilterGroup filters,
            String search,
            Integer first,
            String after,
            String orderBy,
            String orderMode,
            boolean withPagination,
            boolean withFiles,
            String customAttributes) {
        
        log.info("Listing {}s with filters", getEntityType());
        
        String properties = customAttributes != null ? customAttributes 
            : (withFiles ? getPropertiesWithFiles() : getProperties());
        
        String query = String.format("""
            query %ss($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: %s, $orderMode: OrderingMode) {
                %s(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            %s
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
            """, getEntityType(), getOrderingEnum(), getEntityNamePlural(), properties);
        
        Map<String, Object> variables = new HashMap<>();
        if (filters != null) {
            variables.put("filters", convertFilterGroup(filters));
        }
        if (search != null) {
            variables.put("search", search);
        }
        variables.put("first", first != null ? first : 500);
        if (after != null) {
            variables.put("after", after);
        }
        if (orderBy != null) {
            variables.put("orderBy", orderBy);
        }
        if (orderMode != null) {
            variables.put("orderMode", orderMode);
        }
        
        Map<String, Object> result = client.query(query, variables);
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        Map<String, Object> entityData = (Map<String, Object>) data.get(getEntityNamePlural());
        
        return client.processMultiple(entityData, withPagination);
    }

    /**
     * List all entities (handles pagination automatically).
     *
     * @param filters the filters to apply
     * @return list of all matching entities
     */
    public List<Map<String, Object>> listAll(FilterGroup filters) {
        return listAll(filters, null, null, null);
    }

    /**
     * List all entities with ordering (handles pagination automatically).
     *
     * @param filters the filters to apply
     * @param orderBy the field to order by
     * @param orderMode the ordering mode (asc/desc)
     * @param search the search keyword
     * @return list of all matching entities
     */
    public List<Map<String, Object>> listAll(FilterGroup filters, String orderBy, String orderMode, String search) {
        List<Map<String, Object>> allResults = new ArrayList<>();
        String cursor = null;
        
        do {
            PaginatedResult page = list(filters, search, 500, cursor, orderBy, orderMode, true, false, null);
            allResults.addAll(page.getEntities());
            cursor = page.hasNextPage() ? page.getEndCursor() : null;
        } while (cursor != null);
        
        return allResults;
    }

    /**
     * Read an entity by ID.
     *
     * @param id the entity ID
     * @return the entity data or null if not found
     */
    public Map<String, Object> read(String id) {
        return read(id, null, false);
    }

    /**
     * Read an entity by ID with custom attributes.
     *
     * @param id the entity ID
     * @param customAttributes custom attributes to return
     * @param withFiles whether to include files
     * @return the entity data or null if not found
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> read(String id, String customAttributes, boolean withFiles) {
        if (id == null) {
            log.error("Missing parameter: id");
            return null;
        }
        
        log.info("Reading {}: {}", getEntityType(), id);
        
        String properties = customAttributes != null ? customAttributes 
            : (withFiles ? getPropertiesWithFiles() : getProperties());
        
        String query = String.format("""
            query %s($id: String!) {
                %s(id: $id) {
                    %s
                }
            }
            """, getEntityType(), getEntityName(), properties);
        
        Map<String, Object> result = client.query(query, Map.of("id", id));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        Map<String, Object> entity = (Map<String, Object>) data.get(getEntityName());
        
        return client.processMultipleFields(entity);
    }

    /**
     * Read an entity by filters.
     *
     * @param filters the filters to apply
     * @return the first matching entity or null
     */
    public Map<String, Object> read(FilterGroup filters) {
        List<Map<String, Object>> results = list(filters, null, 1, null, null, null);
        return results.isEmpty() ? null : results.get(0);
    }

    /**
     * Delete an entity by ID.
     *
     * @param id the entity ID
     */
    @SuppressWarnings("unchecked")
    public void delete(String id) {
        if (id == null) {
            log.error("Missing parameter: id for delete");
            return;
        }
        
        log.info("Deleting {}: {}", getEntityType(), id);
        
        String mutation = """
            mutation StixCoreObjectDelete($id: ID!) {
                stixCoreObjectEdit(id: $id) {
                    delete
                }
            }
            """;
        
        client.query(mutation, Map.of("id", id));
    }

    /**
     * Update a field on an entity.
     *
     * @param id the entity ID
     * @param key the field key
     * @param value the new value
     * @return the updated entity
     */
    public Map<String, Object> updateField(String id, String key, Object value) {
        return updateField(id, List.of(Map.of("key", key, "value", value)));
    }

    /**
     * Update multiple fields on an entity.
     *
     * @param id the entity ID
     * @param inputs list of field updates
     * @return the updated entity
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> updateField(String id, List<Map<String, Object>> inputs) {
        if (id == null || inputs == null || inputs.isEmpty()) {
            log.error("Missing parameters: id and inputs for update");
            return null;
        }
        
        log.info("Updating {}: {}", getEntityType(), id);
        
        String mutation = """
            mutation StixCoreObjectFieldPatch($id: ID!, $input: [EditInput!]!) {
                stixCoreObjectEdit(id: $id) {
                    fieldPatch(input: $input) {
                        id
                        standard_id
                        entity_type
                    }
                }
            }
            """;
        
        Map<String, Object> result = client.query(mutation, Map.of("id", id, "input", inputs));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        Map<String, Object> edit = (Map<String, Object>) data.get("stixCoreObjectEdit");
        return (Map<String, Object>) edit.get("fieldPatch");
    }

    /**
     * Add a label to an entity.
     *
     * @param id the entity ID
     * @param labelId the label ID
     */
    public void addLabel(String id, String labelId) {
        addRelation(id, labelId, "object-label");
    }

    /**
     * Remove a label from an entity.
     *
     * @param id the entity ID
     * @param labelId the label ID
     */
    public void removeLabel(String id, String labelId) {
        removeRelation(id, labelId, "object-label");
    }

    /**
     * Add a marking definition to an entity.
     *
     * @param id the entity ID
     * @param markingDefinitionId the marking definition ID
     */
    public void addMarkingDefinition(String id, String markingDefinitionId) {
        addRelation(id, markingDefinitionId, "object-marking");
    }

    /**
     * Remove a marking definition from an entity.
     *
     * @param id the entity ID
     * @param markingDefinitionId the marking definition ID
     */
    public void removeMarkingDefinition(String id, String markingDefinitionId) {
        removeRelation(id, markingDefinitionId, "object-marking");
    }

    /**
     * Add an external reference to an entity.
     *
     * @param id the entity ID
     * @param externalReferenceId the external reference ID
     */
    public void addExternalReference(String id, String externalReferenceId) {
        addRelation(id, externalReferenceId, "external-reference");
    }

    /**
     * Remove an external reference from an entity.
     *
     * @param id the entity ID
     * @param externalReferenceId the external reference ID
     */
    public void removeExternalReference(String id, String externalReferenceId) {
        removeRelation(id, externalReferenceId, "external-reference");
    }

    /**
     * Add a relation to an entity.
     *
     * @param id the entity ID
     * @param toId the target entity ID
     * @param relationshipType the relationship type
     */
    protected void addRelation(String id, String toId, String relationshipType) {
        log.info("Adding {} relation to {}: {} -> {}", relationshipType, getEntityType(), id, toId);
        
        String mutation = """
            mutation StixCoreObjectRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
                stixCoreObjectEdit(id: $id) {
                    relationAdd(input: $input) {
                        id
                    }
                }
            }
            """;
        
        client.query(mutation, Map.of(
            "id", id,
            "input", Map.of(
                "toId", toId,
                "relationship_type", relationshipType
            )
        ));
    }

    /**
     * Remove a relation from an entity.
     *
     * @param id the entity ID
     * @param toId the target entity ID
     * @param relationshipType the relationship type
     */
    protected void removeRelation(String id, String toId, String relationshipType) {
        log.info("Removing {} relation from {}: {} -> {}", relationshipType, getEntityType(), id, toId);
        
        String mutation = """
            mutation StixCoreObjectRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                stixCoreObjectEdit(id: $id) {
                    relationDelete(toId: $toId, relationship_type: $relationship_type) {
                        id
                    }
                }
            }
            """;
        
        client.query(mutation, Map.of(
            "id", id,
            "toId", toId,
            "relationship_type", relationshipType
        ));
    }

    /**
     * Convert FilterGroup to a Map for GraphQL.
     */
    protected Map<String, Object> convertFilterGroup(FilterGroup filterGroup) {
        if (filterGroup == null) {
            return null;
        }
        
        Map<String, Object> result = new HashMap<>();
        result.put("mode", filterGroup.getMode());
        
        if (filterGroup.getFilters() != null) {
            List<Map<String, Object>> filters = new ArrayList<>();
            for (FilterGroup.Filter filter : filterGroup.getFilters()) {
                Map<String, Object> filterMap = new HashMap<>();
                filterMap.put("key", filter.getKey());
                filterMap.put("values", filter.getValues());
                filterMap.put("operator", filter.getOperator());
                filterMap.put("mode", filter.getMode());
                filters.add(filterMap);
            }
            result.put("filters", filters);
        }
        
        if (filterGroup.getFilterGroups() != null) {
            List<Map<String, Object>> filterGroups = new ArrayList<>();
            for (FilterGroup group : filterGroup.getFilterGroups()) {
                filterGroups.add(convertFilterGroup(group));
            }
            result.put("filterGroups", filterGroups);
        } else {
            result.put("filterGroups", List.of());
        }
        
        return result;
    }

    /**
     * Build input map from variable arguments.
     *
     * @param args key-value pairs (must be even number of arguments)
     * @return the input map
     */
    protected Map<String, Object> buildInput(Object... args) {
        if (args.length % 2 != 0) {
            throw new IllegalArgumentException("Arguments must be key-value pairs");
        }
        
        Map<String, Object> input = new HashMap<>();
        for (int i = 0; i < args.length; i += 2) {
            String key = (String) args[i];
            Object value = args[i + 1];
            if (value != null) {
                input.put(key, value);
            }
        }
        return input;
    }
}


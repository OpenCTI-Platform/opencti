package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import io.filigran.opencti.model.FilterGroup;
import io.filigran.opencti.model.PaginatedResult;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Entity handler for OpenCTI STIX Core Relationship objects.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
public class StixCoreRelationship extends BaseEntity {

    private static final String STIX_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7";

    private static final String PROPERTIES = """
            id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
            standard_id
            relationship_type
            description
            start_time
            stop_time
            revoked
            confidence
            lang
            created
            modified
            createdBy {
                ... on Identity {
                    id
                    standard_id
                    entity_type
                    name
                }
            }
            objectMarking {
                id
                standard_id
                entity_type
                definition_type
                definition
                x_opencti_order
                x_opencti_color
            }
            objectLabel {
                id
                value
                color
            }
            externalReferences {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                        source_name
                        description
                        url
                        external_id
                    }
                }
            }
            from {
                ... on BasicObject {
                    id
                    entity_type
                    parent_types
                }
                ... on StixObject {
                    standard_id
                }
                ... on AttackPattern { name }
                ... on Campaign { name }
                ... on CourseOfAction { name }
                ... on Individual { name }
                ... on Organization { name }
                ... on Sector { name }
                ... on Indicator { name }
                ... on Infrastructure { name }
                ... on IntrusionSet { name }
                ... on Malware { name }
                ... on ThreatActor { name }
                ... on Tool { name }
                ... on Vulnerability { name }
                ... on Incident { name }
                ... on StixCyberObservable { observable_value }
            }
            to {
                ... on BasicObject {
                    id
                    entity_type
                    parent_types
                }
                ... on StixObject {
                    standard_id
                }
                ... on AttackPattern { name }
                ... on Campaign { name }
                ... on CourseOfAction { name }
                ... on Individual { name }
                ... on Organization { name }
                ... on Sector { name }
                ... on Indicator { name }
                ... on Infrastructure { name }
                ... on IntrusionSet { name }
                ... on Malware { name }
                ... on ThreatActor { name }
                ... on Tool { name }
                ... on Vulnerability { name }
                ... on Incident { name }
                ... on StixCyberObservable { observable_value }
            }
            """;

    public StixCoreRelationship(OpenCTIApiClient client) {
        super(client);
    }

    @Override
    protected String getEntityType() {
        return "StixCoreRelationship";
    }

    @Override
    protected String getEntityName() {
        return "stixCoreRelationship";
    }

    @Override
    protected String getEntityNamePlural() {
        return "stixCoreRelationships";
    }

    @Override
    protected String getProperties() {
        return PROPERTIES;
    }

    @Override
    protected String getOrderingEnum() {
        return "StixCoreRelationshipsOrdering";
    }

    /**
     * Generate a STIX ID for a relationship.
     *
     * @param relationshipType the relationship type
     * @param sourceRef the source entity reference ID
     * @param targetRef the target entity reference ID
     * @param startTime optional start time
     * @param stopTime optional stop time
     * @return the STIX ID
     */
    public static String generateId(String relationshipType, String sourceRef, String targetRef, String startTime, String stopTime) {
        StringBuilder dataBuilder = new StringBuilder();
        dataBuilder.append("{\"relationship_type\":\"").append(relationshipType).append("\"");
        dataBuilder.append(",\"source_ref\":\"").append(sourceRef).append("\"");
        dataBuilder.append(",\"target_ref\":\"").append(targetRef).append("\"");
        if (startTime != null) {
            dataBuilder.append(",\"start_time\":\"").append(startTime).append("\"");
        }
        if (stopTime != null) {
            dataBuilder.append(",\"stop_time\":\"").append(stopTime).append("\"");
        }
        dataBuilder.append("}");
        
        UUID uuid = UUID.nameUUIDFromBytes((STIX_NAMESPACE + dataBuilder.toString()).getBytes(StandardCharsets.UTF_8));
        return "relationship--" + uuid;
    }

    /**
     * List relationships with specific parameters.
     *
     * @param fromOrToId filter by source or target entity ID
     * @param fromId filter by source entity ID
     * @param toId filter by target entity ID
     * @param relationshipType filter by relationship type
     * @param first number of results to return
     * @param after cursor for pagination
     * @return list of relationships
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> list(
            String fromOrToId,
            String fromId,
            String toId,
            String relationshipType,
            Integer first,
            String after) {
        
        log.info("Listing stix_core_relationships: fromId={}, toId={}, type={}", fromId, toId, relationshipType);
        
        String query = """
            query StixCoreRelationships($fromOrToId: [String], $fromId: [String], $toId: [String], $relationship_type: [String], $first: Int, $after: ID) {
                stixCoreRelationships(fromOrToId: $fromOrToId, fromId: $fromId, toId: $toId, relationship_type: $relationship_type, first: $first, after: $after) {
                    edges {
                        node {
                            """ + PROPERTIES + """
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
        
        Map<String, Object> variables = new HashMap<>();
        if (fromOrToId != null) variables.put("fromOrToId", List.of(fromOrToId));
        if (fromId != null) variables.put("fromId", List.of(fromId));
        if (toId != null) variables.put("toId", List.of(toId));
        if (relationshipType != null) variables.put("relationship_type", List.of(relationshipType));
        variables.put("first", first != null ? first : 100);
        if (after != null) variables.put("after", after);
        
        Map<String, Object> result = client.query(query, variables);
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        Map<String, Object> relationships = (Map<String, Object>) data.get("stixCoreRelationships");
        
        return client.processMultiple(relationships);
    }

    /**
     * Create a new relationship.
     *
     * @param fromId the source entity ID (required)
     * @param toId the target entity ID (required)
     * @param relationshipType the relationship type (required)
     * @param params additional parameters
     * @return the created relationship
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String fromId, String toId, String relationshipType, Object... params) {
        if (fromId == null || toId == null || relationshipType == null) {
            log.error("Missing required parameters: fromId, toId, or relationship_type");
            return null;
        }
        
        log.info("Creating stix_core_relationship: {} --{}-> {}", fromId, relationshipType, toId);
        
        Map<String, Object> input = buildInput(params);
        input.put("fromId", fromId);
        input.put("toId", toId);
        input.put("relationship_type", relationshipType);
        
        String mutation = """
            mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
                stixCoreRelationshipAdd(input: $input) {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
            }
            """;
        
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("stixCoreRelationshipAdd"));
    }

    /**
     * Create a relationship with all parameters.
     *
     * @param stixId optional STIX ID
     * @param fromId the source entity ID
     * @param toId the target entity ID
     * @param relationshipType the relationship type
     * @param description optional description
     * @param startTime optional start time
     * @param stopTime optional stop time
     * @param createdBy optional creator identity ID
     * @param objectMarking optional marking definition IDs
     * @param objectLabel optional label IDs
     * @param externalReferences optional external reference IDs
     * @param killChainPhases optional kill chain phase IDs
     * @param revoked whether the relationship is revoked
     * @param confidence optional confidence level
     * @param created optional creation date
     * @param modified optional modification date
     * @param update whether to update if exists
     * @return the created relationship
     */
    public Map<String, Object> create(
            String stixId,
            String fromId,
            String toId,
            String relationshipType,
            String description,
            String startTime,
            String stopTime,
            String createdBy,
            List<String> objectMarking,
            List<String> objectLabel,
            List<String> externalReferences,
            List<String> killChainPhases,
            Boolean revoked,
            Integer confidence,
            String created,
            String modified,
            boolean update) {
        
        return create(fromId, toId, relationshipType,
            "stix_id", stixId,
            "description", description,
            "start_time", startTime,
            "stop_time", stopTime,
            "createdBy", createdBy,
            "objectMarking", objectMarking,
            "objectLabel", objectLabel,
            "externalReferences", externalReferences,
            "killChainPhases", killChainPhases,
            "revoked", revoked,
            "confidence", confidence,
            "created", created,
            "modified", modified,
            "update", update
        );
    }

    /**
     * Update a relationship field.
     *
     * @param id the relationship ID
     * @param inputs list of field updates
     * @return the updated relationship
     */
    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> updateField(String id, List<Map<String, Object>> inputs) {
        if (id == null || inputs == null || inputs.isEmpty()) {
            log.error("Missing parameters: id and inputs for update");
            return null;
        }
        
        log.info("Updating stix_core_relationship: {}", id);
        
        String mutation = """
            mutation StixCoreRelationshipEdit($id: ID!, $input: [EditInput]!) {
                stixCoreRelationshipEdit(id: $id) {
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
        Map<String, Object> edit = (Map<String, Object>) data.get("stixCoreRelationshipEdit");
        return (Map<String, Object>) edit.get("fieldPatch");
    }

    /**
     * Delete a relationship.
     *
     * @param id the relationship ID
     */
    @Override
    public void delete(String id) {
        if (id == null) {
            log.error("Missing parameter: id for delete");
            return;
        }
        
        log.info("Deleting stix_core_relationship: {}", id);
        
        String mutation = """
            mutation StixCoreRelationshipEdit($id: ID!) {
                stixCoreRelationshipEdit(id: $id) {
                    delete
                }
            }
            """;
        
        client.query(mutation, Map.of("id", id));
    }

    /**
     * Import a relationship from STIX2.
     *
     * @param stixRelation the STIX2 relationship object
     * @param extras extra parameters
     * @param update whether to update if exists
     * @return the imported relationship
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> importFromStix2(Map<String, Object> stixRelation, Map<String, Object> extras, boolean update) {
        if (stixRelation == null) {
            log.error("Missing parameter: stixRelation");
            return null;
        }
        
        return create(
            (String) stixRelation.get("id"),
            (String) stixRelation.get("source_ref"),
            (String) stixRelation.get("target_ref"),
            (String) stixRelation.get("relationship_type"),
            (String) stixRelation.get("description"),
            (String) stixRelation.get("start_time"),
            (String) stixRelation.get("stop_time"),
            extras != null ? (String) extras.get("created_by_id") : null,
            extras != null ? (List<String>) extras.get("object_marking_ids") : null,
            extras != null ? (List<String>) extras.get("object_label_ids") : null,
            extras != null ? (List<String>) extras.get("external_references_ids") : null,
            extras != null ? (List<String>) extras.get("kill_chain_phases_ids") : null,
            stixRelation.containsKey("revoked") ? (Boolean) stixRelation.get("revoked") : null,
            stixRelation.containsKey("confidence") ? ((Number) stixRelation.get("confidence")).intValue() : null,
            (String) stixRelation.get("created"),
            (String) stixRelation.get("modified"),
            update
        );
    }
}


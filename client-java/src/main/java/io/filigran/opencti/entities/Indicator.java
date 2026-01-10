package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Entity handler for OpenCTI Indicator objects.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
public class Indicator extends BaseEntity {

    private static final String STIX_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7";

    private static final String PROPERTIES = """
            id
            standard_id
            entity_type
            parent_types
            spec_version
            created_at
            updated_at
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
            revoked
            confidence
            created
            modified
            name
            description
            pattern_type
            pattern_version
            pattern
            indicator_types
            valid_from
            valid_until
            x_opencti_score
            x_opencti_detection
            x_opencti_main_observable_type
            x_mitre_platforms
            killChainPhases {
                id
                standard_id
                entity_type
                kill_chain_name
                phase_name
                x_opencti_order
            }
            observables {
                edges {
                    node {
                        id
                        standard_id
                        entity_type
                    }
                }
            }
            """;

    public Indicator(OpenCTIApiClient client) {
        super(client);
    }

    @Override
    protected String getEntityType() {
        return "Indicator";
    }

    @Override
    protected String getEntityName() {
        return "indicator";
    }

    @Override
    protected String getEntityNamePlural() {
        return "indicators";
    }

    @Override
    protected String getProperties() {
        return PROPERTIES;
    }

    @Override
    protected String getOrderingEnum() {
        return "IndicatorsOrdering";
    }

    /**
     * Generate a STIX ID for an Indicator based on its pattern.
     *
     * @param pattern the indicator pattern
     * @return the STIX ID
     */
    public static String generateId(String pattern) {
        String normalizedPattern = pattern.strip();
        String data = "{\"pattern\":\"" + normalizedPattern + "\"}";
        UUID uuid = UUID.nameUUIDFromBytes((STIX_NAMESPACE + data).getBytes(StandardCharsets.UTF_8));
        return "indicator--" + uuid;
    }

    /**
     * Create a new Indicator with required parameters.
     *
     * @param name the indicator name
     * @param pattern the indicator pattern
     * @param patternType the pattern type (e.g., "stix")
     * @param mainObservableType the main observable type
     * @param params additional parameters
     * @return the created indicator
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String name, String pattern, String patternType, String mainObservableType, Object... params) {
        if (pattern == null || patternType == null || mainObservableType == null) {
            log.error("Missing required parameters: pattern, pattern_type, or x_opencti_main_observable_type");
            return null;
        }
        
        // Normalize File to StixFile
        if ("File".equals(mainObservableType)) {
            mainObservableType = "StixFile";
        }
        
        String indicatorName = name != null ? name : pattern;
        log.info("Creating Indicator: {}", indicatorName);
        
        Map<String, Object> input = buildInput(params);
        input.put("name", indicatorName);
        input.put("pattern", pattern);
        input.put("pattern_type", patternType);
        input.put("x_opencti_main_observable_type", mainObservableType);
        
        String mutation = """
            mutation IndicatorAdd($input: IndicatorAddInput!) {
                indicatorAdd(input: $input) {
                    id
                    standard_id
                    entity_type
                    parent_types
                    observables {
                        edges {
                            node {
                                id
                                standard_id
                                entity_type
                            }
                        }
                    }
                }
            }
            """;
        
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("indicatorAdd"));
    }

    /**
     * Create a new Indicator with all parameters.
     *
     * @param stixId optional STIX ID
     * @param name the indicator name
     * @param description optional description
     * @param pattern the indicator pattern
     * @param patternType the pattern type
     * @param patternVersion optional pattern version
     * @param mainObservableType the main observable type
     * @param indicatorTypes optional list of indicator types
     * @param validFrom optional valid from date
     * @param validUntil optional valid until date
     * @param score optional score (0-100)
     * @param detection optional detection flag
     * @param mitrePlatforms optional MITRE platforms
     * @param killChainPhases optional kill chain phase IDs
     * @param createdBy optional creator identity ID
     * @param objectMarking optional marking definition IDs
     * @param objectLabel optional label IDs
     * @param externalReferences optional external reference IDs
     * @param revoked whether the indicator is revoked
     * @param confidence optional confidence level
     * @param created optional creation date
     * @param modified optional modification date
     * @param createObservables whether to create observables
     * @param update whether to update if exists
     * @return the created indicator
     */
    public Map<String, Object> create(
            String stixId,
            String name,
            String description,
            String pattern,
            String patternType,
            String patternVersion,
            String mainObservableType,
            List<String> indicatorTypes,
            String validFrom,
            String validUntil,
            Integer score,
            Boolean detection,
            List<String> mitrePlatforms,
            List<String> killChainPhases,
            String createdBy,
            List<String> objectMarking,
            List<String> objectLabel,
            List<String> externalReferences,
            Boolean revoked,
            Integer confidence,
            String created,
            String modified,
            boolean createObservables,
            boolean update) {
        
        return create(name, pattern, patternType, mainObservableType,
            "stix_id", stixId,
            "description", description,
            "pattern_version", patternVersion,
            "indicator_types", indicatorTypes,
            "valid_from", validFrom,
            "valid_until", validUntil,
            "x_opencti_score", score != null ? score : 50,
            "x_opencti_detection", detection != null ? detection : false,
            "x_mitre_platforms", mitrePlatforms,
            "killChainPhases", killChainPhases,
            "createdBy", createdBy,
            "objectMarking", objectMarking,
            "objectLabel", objectLabel,
            "externalReferences", externalReferences,
            "revoked", revoked,
            "confidence", confidence,
            "created", created,
            "modified", modified,
            "createObservables", createObservables,
            "update", update
        );
    }

    /**
     * Add a Stix-Cyber-Observable to this Indicator (based-on relationship).
     *
     * @param indicatorId the indicator ID
     * @param observableId the observable ID
     * @return true if successful
     */
    @SuppressWarnings("unchecked")
    public boolean addStixCyberObservable(String indicatorId, String observableId) {
        if (indicatorId == null || observableId == null) {
            log.error("Missing parameters: indicatorId and observableId");
            return false;
        }
        
        // Check if already exists
        Map<String, Object> indicator = read(indicatorId);
        if (indicator == null) {
            log.error("Indicator not found: {}", indicatorId);
            return false;
        }
        
        List<String> observableIds = (List<String>) indicator.get("observablesIds");
        if (observableIds != null && observableIds.contains(observableId)) {
            return true; // Already exists
        }
        
        log.info("Adding Stix-Observable to Indicator: {} -> {}", indicatorId, observableId);
        
        String mutation = """
            mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
                stixCoreRelationshipAdd(input: $input) {
                    id
                }
            }
            """;
        
        client.query(mutation, Map.of(
            "input", Map.of(
                "fromId", indicatorId,
                "toId", observableId,
                "relationship_type", "based-on"
            )
        ));
        
        return true;
    }

    /**
     * Import an Indicator from a STIX2 object.
     *
     * @param stixObject the STIX2 indicator object
     * @param extras extra parameters (created_by_id, object_marking_ids, etc.)
     * @param update whether to update if exists
     * @return the imported indicator
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> importFromStix2(Map<String, Object> stixObject, Map<String, Object> extras, boolean update) {
        if (stixObject == null) {
            log.error("Missing parameter: stixObject");
            return null;
        }
        
        String mainObservableType = (String) stixObject.get("x_opencti_main_observable_type");
        if (mainObservableType == null) {
            mainObservableType = "Unknown";
        }
        
        return create(
            (String) stixObject.get("id"),
            stixObject.containsKey("name") ? (String) stixObject.get("name") : (String) stixObject.get("pattern"),
            (String) stixObject.get("description"),
            (String) stixObject.get("pattern"),
            (String) stixObject.get("pattern_type"),
            (String) stixObject.get("pattern_version"),
            mainObservableType,
            (List<String>) stixObject.get("indicator_types"),
            (String) stixObject.get("valid_from"),
            (String) stixObject.get("valid_until"),
            stixObject.containsKey("x_opencti_score") ? ((Number) stixObject.get("x_opencti_score")).intValue() : 50,
            stixObject.containsKey("x_opencti_detection") ? (Boolean) stixObject.get("x_opencti_detection") : false,
            (List<String>) stixObject.get("x_mitre_platforms"),
            extras != null ? (List<String>) extras.get("kill_chain_phases_ids") : null,
            extras != null ? (String) extras.get("created_by_id") : null,
            extras != null ? (List<String>) extras.get("object_marking_ids") : null,
            extras != null ? (List<String>) extras.get("object_label_ids") : null,
            extras != null ? (List<String>) extras.get("external_references_ids") : null,
            stixObject.containsKey("revoked") ? (Boolean) stixObject.get("revoked") : null,
            stixObject.containsKey("confidence") ? ((Number) stixObject.get("confidence")).intValue() : null,
            (String) stixObject.get("created"),
            (String) stixObject.get("modified"),
            stixObject.containsKey("x_opencti_create_observables") ? (Boolean) stixObject.get("x_opencti_create_observables") : false,
            update
        );
    }
}


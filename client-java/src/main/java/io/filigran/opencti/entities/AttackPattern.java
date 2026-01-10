package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Entity handler for OpenCTI Attack Pattern objects.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
public class AttackPattern extends BaseEntity {

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
            aliases
            x_mitre_platforms
            x_mitre_permissions_required
            x_mitre_detection
            x_mitre_id
            killChainPhases {
                id
                standard_id
                entity_type
                kill_chain_name
                phase_name
                x_opencti_order
            }
            """;

    public AttackPattern(OpenCTIApiClient client) {
        super(client);
    }

    @Override
    protected String getEntityType() {
        return "AttackPattern";
    }

    @Override
    protected String getEntityName() {
        return "attackPattern";
    }

    @Override
    protected String getEntityNamePlural() {
        return "attackPatterns";
    }

    @Override
    protected String getProperties() {
        return PROPERTIES;
    }

    @Override
    protected String getOrderingEnum() {
        return "AttackPatternsOrdering";
    }

    /**
     * Generate a STIX ID for an Attack Pattern.
     *
     * @param name the attack pattern name
     * @param mitreId optional MITRE ATT&CK ID
     * @return the STIX ID
     */
    public static String generateId(String name, String mitreId) {
        String normalizedName = name.toLowerCase().strip();
        String data;
        if (mitreId != null && !mitreId.isBlank()) {
            data = "{\"name\":\"" + normalizedName + "\",\"x_mitre_id\":\"" + mitreId + "\"}";
        } else {
            data = "{\"name\":\"" + normalizedName + "\"}";
        }
        UUID uuid = UUID.nameUUIDFromBytes((STIX_NAMESPACE + data).getBytes(StandardCharsets.UTF_8));
        return "attack-pattern--" + uuid;
    }

    /**
     * Create a new Attack Pattern.
     *
     * @param name the attack pattern name (required)
     * @param params additional parameters
     * @return the created attack pattern
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String name, Object... params) {
        if (name == null || name.isBlank()) {
            log.error("Missing required parameter: name");
            return null;
        }
        
        log.info("Creating AttackPattern: {}", name);
        
        Map<String, Object> input = buildInput(params);
        input.put("name", name);
        
        String mutation = """
            mutation AttackPatternAdd($input: AttackPatternAddInput!) {
                attackPatternAdd(input: $input) {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
            }
            """;
        
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("attackPatternAdd"));
    }
}


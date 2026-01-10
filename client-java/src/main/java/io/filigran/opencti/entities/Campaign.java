package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * Entity handler for OpenCTI Campaign objects.
 *
 * @author Filigran Team
 * @since 6.9.6
 */
@Slf4j
public class Campaign extends BaseEntity {

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
            first_seen
            last_seen
            objective
            """;

    public Campaign(OpenCTIApiClient client) {
        super(client);
    }

    @Override
    protected String getEntityType() {
        return "Campaign";
    }

    @Override
    protected String getEntityName() {
        return "campaign";
    }

    @Override
    protected String getEntityNamePlural() {
        return "campaigns";
    }

    @Override
    protected String getProperties() {
        return PROPERTIES;
    }

    @Override
    protected String getOrderingEnum() {
        return "CampaignsOrdering";
    }

    /**
     * Create a new Campaign.
     *
     * @param name the campaign name (required)
     * @param params additional parameters
     * @return the created campaign
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String name, Object... params) {
        if (name == null || name.isBlank()) {
            log.error("Missing required parameter: name");
            return null;
        }
        
        log.info("Creating Campaign: {}", name);
        
        Map<String, Object> input = buildInput(params);
        input.put("name", name);
        
        String mutation = """
            mutation CampaignAdd($input: CampaignAddInput!) {
                campaignAdd(input: $input) {
                    id
                    standard_id
                    entity_type
                    parent_types
                }
            }
            """;
        
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("campaignAdd"));
    }
}


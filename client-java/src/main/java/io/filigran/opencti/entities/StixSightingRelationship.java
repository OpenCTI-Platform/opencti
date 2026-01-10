package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class StixSightingRelationship extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            description first_seen last_seen count x_opencti_negative attribute_count confidence
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            from { ... on BasicObject { id entity_type } ... on StixObject { standard_id } }
            to { ... on BasicObject { id entity_type } ... on StixObject { standard_id } }
            """;

    public StixSightingRelationship(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "StixSightingRelationship"; }
    @Override protected String getEntityName() { return "stixSightingRelationship"; }
    @Override protected String getEntityNamePlural() { return "stixSightingRelationships"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "StixSightingRelationshipsOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String fromId, String toId, Object... params) {
        if (fromId == null || toId == null) { log.error("Missing required parameters: fromId, toId"); return null; }
        log.info("Creating StixSightingRelationship: {} -> {}", fromId, toId);
        Map<String, Object> input = buildInput(params);
        input.put("fromId", fromId);
        input.put("toId", toId);
        String mutation = "mutation StixSightingRelationshipAdd($input: StixSightingRelationshipAddInput!) { stixSightingRelationshipAdd(input: $input) { id standard_id entity_type parent_types } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("stixSightingRelationshipAdd"));
    }
}


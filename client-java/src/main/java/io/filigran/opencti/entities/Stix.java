package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class Stix extends BaseEntity {
    private static final String PROPERTIES = "id standard_id entity_type parent_types";

    public Stix(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "Stix"; }
    @Override protected String getEntityName() { return "stix"; }
    @Override protected String getEntityNamePlural() { return "stixObjectOrStixRelationships"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "StixObjectOrStixRelationshipsOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> getStix(String id) {
        log.info("Getting STIX content for: {}", id);
        String query = "query StixQuery($id: String!) { stix(id: $id) }";
        Map<String, Object> result = client.query(query, Map.of("id", id));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        String stixJson = (String) data.get("stix");
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(stixJson, 
                new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
        } catch (Exception e) {
            log.error("Failed to parse STIX content", e);
            return null;
        }
    }
}


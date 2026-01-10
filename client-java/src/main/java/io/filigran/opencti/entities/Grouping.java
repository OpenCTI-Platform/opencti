package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class Grouping extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            revoked confidence created modified name description context
            objects { edges { node { ... on BasicObject { id entity_type standard_id } } } }
            """;

    public Grouping(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "Grouping"; }
    @Override protected String getEntityName() { return "grouping"; }
    @Override protected String getEntityNamePlural() { return "groupings"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "GroupingsOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String name, String context, Object... params) {
        if (name == null || name.isBlank() || context == null) { 
            log.error("Missing required parameters: name and context"); 
            return null; 
        }
        log.info("Creating Grouping: {}", name);
        Map<String, Object> input = buildInput(params);
        input.put("name", name);
        input.put("context", context);
        String mutation = "mutation GroupingAdd($input: GroupingAddInput!) { groupingAdd(input: $input) { id standard_id entity_type parent_types } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("groupingAdd"));
    }
}


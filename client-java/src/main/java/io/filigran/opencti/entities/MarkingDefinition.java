package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class MarkingDefinition extends BaseEntity {
    private static final String PROPERTIES = "id standard_id entity_type definition_type definition x_opencti_order x_opencti_color created modified";

    public MarkingDefinition(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "MarkingDefinition"; }
    @Override protected String getEntityName() { return "markingDefinition"; }
    @Override protected String getEntityNamePlural() { return "markingDefinitions"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "MarkingDefinitionsOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String definitionType, String definition, int order, Object... params) {
        if (definitionType == null || definition == null) { log.error("Missing required parameters"); return null; }
        log.info("Creating MarkingDefinition: {} - {}", definitionType, definition);
        Map<String, Object> input = buildInput(params);
        input.put("definition_type", definitionType);
        input.put("definition", definition);
        input.put("x_opencti_order", order);
        String mutation = "mutation MarkingDefinitionAdd($input: MarkingDefinitionAddInput!) { markingDefinitionAdd(input: $input) { id standard_id entity_type definition_type definition x_opencti_order x_opencti_color } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("markingDefinitionAdd"));
    }

    @Override
    public void delete(String id) {
        if (id == null) { log.error("Missing parameter: id for delete"); return; }
        log.info("Deleting MarkingDefinition: {}", id);
        String mutation = "mutation MarkingDefinitionDelete($id: ID!) { markingDefinitionDelete(id: $id) }";
        client.query(mutation, Map.of("id", id));
    }
}


package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class Label extends BaseEntity {
    private static final String PROPERTIES = "id value color created_at updated_at";

    public Label(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "Label"; }
    @Override protected String getEntityName() { return "label"; }
    @Override protected String getEntityNamePlural() { return "labels"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "LabelsOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String value, Object... params) {
        if (value == null || value.isBlank()) { log.error("Missing required parameter: value"); return null; }
        log.info("Creating Label: {}", value);
        Map<String, Object> input = buildInput(params);
        input.put("value", value);
        String mutation = "mutation LabelAdd($input: LabelAddInput!) { labelAdd(input: $input) { id value color } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("labelAdd"));
    }

    @Override
    public void delete(String id) {
        if (id == null) { log.error("Missing parameter: id for delete"); return; }
        log.info("Deleting Label: {}", id);
        String mutation = "mutation LabelDelete($id: ID!) { labelDelete(id: $id) }";
        client.query(mutation, Map.of("id", id));
    }
}


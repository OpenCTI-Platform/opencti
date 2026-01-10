package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class ExternalReference extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type source_name description url hash external_id created modified
            """;

    public ExternalReference(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "ExternalReference"; }
    @Override protected String getEntityName() { return "externalReference"; }
    @Override protected String getEntityNamePlural() { return "externalReferences"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "ExternalReferencesOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String sourceName, Object... params) {
        if (sourceName == null || sourceName.isBlank()) { log.error("Missing required parameter: source_name"); return null; }
        log.info("Creating ExternalReference: {}", sourceName);
        Map<String, Object> input = buildInput(params);
        input.put("source_name", sourceName);
        String mutation = "mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) { externalReferenceAdd(input: $input) { id standard_id entity_type } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("externalReferenceAdd"));
    }
}


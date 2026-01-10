package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class StixCyberObservable extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            observable_value x_opencti_score x_opencti_description
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            indicators { edges { node { id standard_id entity_type name pattern pattern_type } } }
            """;

    public StixCyberObservable(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "StixCyberObservable"; }
    @Override protected String getEntityName() { return "stixCyberObservable"; }
    @Override protected String getEntityNamePlural() { return "stixCyberObservables"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "StixCyberObservablesOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String type, Map<String, Object> simpleObservableValue, Object... params) {
        if (type == null || simpleObservableValue == null) { 
            log.error("Missing required parameters: type and simpleObservableValue"); 
            return null; 
        }
        log.info("Creating StixCyberObservable of type: {}", type);
        Map<String, Object> input = buildInput(params);
        input.put("type", type);
        input.putAll(simpleObservableValue);
        String mutation = "mutation StixCyberObservableAdd($type: String!, $stixCyberObservable: StixCyberObservableAddInput!) { stixCyberObservableAdd(type: $type, stixCyberObservable: $stixCyberObservable) { id standard_id entity_type observable_value } }";
        Map<String, Object> result = client.query(mutation, Map.of("type", type, "stixCyberObservable", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("stixCyberObservableAdd"));
    }

    public Map<String, Object> createSimple(String type, String value, Object... params) {
        return create(type, Map.of(getValueFieldForType(type), value), params);
    }

    private String getValueFieldForType(String type) {
        return switch (type.toLowerCase()) {
            case "ipv4-addr", "ipv6-addr" -> "value";
            case "domain-name" -> "value";
            case "url" -> "value";
            case "email-addr" -> "value";
            case "file", "stixfile" -> "name";
            default -> "value";
        };
    }

    public Map<String, Object> promoteToIndicator(String observableId) {
        log.info("Promoting observable to indicator: {}", observableId);
        String mutation = "mutation PromoteObservable($id: ID!) { stixCyberObservableEdit(id: $id) { promoteToIndicator { id standard_id entity_type } } }";
        @SuppressWarnings("unchecked")
        Map<String, Object> result = client.query(mutation, Map.of("id", observableId));
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        @SuppressWarnings("unchecked")
        Map<String, Object> edit = (Map<String, Object>) data.get("stixCyberObservableEdit");
        return (Map<String, Object>) edit.get("promoteToIndicator");
    }
}


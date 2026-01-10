package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.List;
import java.util.Map;

@Slf4j
public class Report extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            revoked confidence created modified name description report_types published
            objects { edges { node { ... on BasicObject { id entity_type standard_id } } } }
            """;

    public Report(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "Report"; }
    @Override protected String getEntityName() { return "report"; }
    @Override protected String getEntityNamePlural() { return "reports"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "ReportsOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String name, String published, Object... params) {
        if (name == null || name.isBlank() || published == null) { 
            log.error("Missing required parameters: name and published"); 
            return null; 
        }
        log.info("Creating Report: {}", name);
        Map<String, Object> input = buildInput(params);
        input.put("name", name);
        input.put("published", published);
        String mutation = "mutation ReportAdd($input: ReportAddInput!) { reportAdd(input: $input) { id standard_id entity_type parent_types } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("reportAdd"));
    }

    public void addStixObjectOrRelationship(String reportId, String stixObjectOrRelationshipId) {
        log.info("Adding object to Report: {} -> {}", reportId, stixObjectOrRelationshipId);
        String mutation = """
            mutation ReportAddRelation($id: ID!, $input: StixRefRelationshipAddInput!) {
                reportEdit(id: $id) { relationAdd(input: $input) { id } }
            }
            """;
        client.query(mutation, Map.of("id", reportId, "input", Map.of("toId", stixObjectOrRelationshipId, "relationship_type", "object")));
    }

    public void removeStixObjectOrRelationship(String reportId, String stixObjectOrRelationshipId) {
        log.info("Removing object from Report: {} -> {}", reportId, stixObjectOrRelationshipId);
        String mutation = """
            mutation ReportRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
                reportEdit(id: $id) { relationDelete(toId: $toId, relationship_type: $relationship_type) { id } }
            }
            """;
        client.query(mutation, Map.of("id", reportId, "toId", stixObjectOrRelationshipId, "relationship_type", "object"));
    }
}


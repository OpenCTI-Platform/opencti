package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class CourseOfAction extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            revoked confidence created modified name description x_mitre_id
            """;

    public CourseOfAction(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "CourseOfAction"; }
    @Override protected String getEntityName() { return "courseOfAction"; }
    @Override protected String getEntityNamePlural() { return "coursesOfAction"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "CoursesOfActionOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String name, Object... params) {
        if (name == null || name.isBlank()) { log.error("Missing required parameter: name"); return null; }
        log.info("Creating CourseOfAction: {}", name);
        Map<String, Object> input = buildInput(params);
        input.put("name", name);
        String mutation = "mutation CourseOfActionAdd($input: CourseOfActionAddInput!) { courseOfActionAdd(input: $input) { id standard_id entity_type parent_types } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("courseOfActionAdd"));
    }
}


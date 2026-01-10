package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class Note extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            revoked confidence created modified content abstract attribute_abstract authors note_types likelihood
            objects { edges { node { ... on BasicObject { id entity_type standard_id } } } }
            """;

    public Note(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "Note"; }
    @Override protected String getEntityName() { return "note"; }
    @Override protected String getEntityNamePlural() { return "notes"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "NotesOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String content, Object... params) {
        if (content == null || content.isBlank()) { log.error("Missing required parameter: content"); return null; }
        log.info("Creating Note");
        Map<String, Object> input = buildInput(params);
        input.put("content", content);
        String mutation = "mutation NoteAdd($input: NoteAddInput!) { noteAdd(input: $input) { id standard_id entity_type parent_types } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("noteAdd"));
    }
}


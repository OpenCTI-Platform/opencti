package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class ThreatActor extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            revoked confidence created modified name description aliases threat_actor_types first_seen last_seen roles goals sophistication resource_level primary_motivation secondary_motivations
            """;

    public ThreatActor(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "ThreatActor"; }
    @Override protected String getEntityName() { return "threatActor"; }
    @Override protected String getEntityNamePlural() { return "threatActorsGroup"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "ThreatActorsOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String name, Object... params) {
        if (name == null || name.isBlank()) { log.error("Missing required parameter: name"); return null; }
        log.info("Creating ThreatActor: {}", name);
        Map<String, Object> input = buildInput(params);
        input.put("name", name);
        String mutation = "mutation ThreatActorGroupAdd($input: ThreatActorGroupAddInput!) { threatActorGroupAdd(input: $input) { id standard_id entity_type parent_types } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("threatActorGroupAdd"));
    }
}


package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class Identity extends BaseEntity {
    private static final String PROPERTIES = """
            id standard_id entity_type parent_types spec_version created_at updated_at
            createdBy { ... on Identity { id standard_id entity_type name } }
            objectMarking { id standard_id definition_type definition x_opencti_order x_opencti_color }
            objectLabel { id value color }
            revoked confidence created modified name description identity_class roles contact_information x_opencti_aliases
            """;

    public Identity(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "Identity"; }
    @Override protected String getEntityName() { return "identity"; }
    @Override protected String getEntityNamePlural() { return "identities"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "IdentitiesOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String name, String identityClass, Object... params) {
        if (name == null || name.isBlank()) { log.error("Missing required parameter: name"); return null; }
        log.info("Creating Identity: {}", name);
        Map<String, Object> input = buildInput(params);
        input.put("name", name);
        input.put("type", identityClass != null ? identityClass : "organization");
        String mutation = "mutation IdentityAdd($input: IdentityAddInput!) { identityAdd(input: $input) { id standard_id entity_type parent_types } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("identityAdd"));
    }
}


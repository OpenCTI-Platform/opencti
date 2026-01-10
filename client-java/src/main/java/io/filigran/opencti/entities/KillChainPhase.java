package io.filigran.opencti.entities;

import io.filigran.opencti.OpenCTIApiClient;
import lombok.extern.slf4j.Slf4j;
import java.util.Map;

@Slf4j
public class KillChainPhase extends BaseEntity {
    private static final String PROPERTIES = "id standard_id entity_type kill_chain_name phase_name x_opencti_order created modified";

    public KillChainPhase(OpenCTIApiClient client) { super(client); }
    @Override protected String getEntityType() { return "KillChainPhase"; }
    @Override protected String getEntityName() { return "killChainPhase"; }
    @Override protected String getEntityNamePlural() { return "killChainPhases"; }
    @Override protected String getProperties() { return PROPERTIES; }
    @Override protected String getOrderingEnum() { return "KillChainPhasesOrdering"; }

    @SuppressWarnings("unchecked")
    public Map<String, Object> create(String killChainName, String phaseName, Object... params) {
        if (killChainName == null || phaseName == null) { log.error("Missing required parameters"); return null; }
        log.info("Creating KillChainPhase: {} - {}", killChainName, phaseName);
        Map<String, Object> input = buildInput(params);
        input.put("kill_chain_name", killChainName);
        input.put("phase_name", phaseName);
        String mutation = "mutation KillChainPhaseAdd($input: KillChainPhaseAddInput!) { killChainPhaseAdd(input: $input) { id standard_id entity_type kill_chain_name phase_name x_opencti_order } }";
        Map<String, Object> result = client.query(mutation, Map.of("input", input));
        Map<String, Object> data = (Map<String, Object>) result.get("data");
        return client.processMultipleFields((Map<String, Object>) data.get("killChainPhaseAdd"));
    }

    @Override
    public void delete(String id) {
        if (id == null) { log.error("Missing parameter: id for delete"); return; }
        log.info("Deleting KillChainPhase: {}", id);
        String mutation = "mutation KillChainPhaseDelete($id: ID!) { killChainPhaseDelete(id: $id) }";
        client.query(mutation, Map.of("id", id));
    }
}


import { APIRequestContext } from '@playwright/test';
import { v4 as uuid } from 'uuid';
import { graphqlRequest } from './graphql.data';

export const HUNT_SIGMA_RULE = `title: E2E encoded PowerShell command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: ' -enc '
  condition: selection
`;

export interface SeededHunt {
  huntId: string;
  runId: string;
  connectorId: string;
  securityPlatformId: string;
}

/**
 * Creates an active hunt with one completed run, the way a hunt connector would:
 * the connector registers its security platform, the run is started on it, then
 * the connector reports the run completed with hits.
 */
export const seedHuntWithCompletedRun = async (request: APIRequestContext, name: string): Promise<SeededHunt> => {
  const connectorId = uuid();
  await graphqlRequest(request, `
    mutation {
      registerConnector(input: {
        id: "${connectorId}", name: ${JSON.stringify(`E2E hunt connector ${connectorId}`)},
        type: INTERNAL_HUNT, scope: ["splunk"], auto: false, only_contextual: false
      }) { id }
    }
  `, 'Register the hunt connector');
  const registration = await graphqlRequest<{ huntConnectorRegister: { securityPlatform: { id: string } } }>(request, `
    mutation {
      huntConnectorRegister(input: {
        connector_id: "${connectorId}", platform: "splunk", languages: ["spl"],
        security_platform_name: ${JSON.stringify(`E2E Splunk ${connectorId}`)}
      }) { securityPlatform { id } }
    }
  `, 'Register the hunt security platform');
  const securityPlatformId = registration.huntConnectorRegister.securityPlatform.id;
  const hunt = await graphqlRequest<{ huntAdd: { id: string } }>(request, `
    mutation {
      huntAdd(input: {
        name: ${JSON.stringify(name)},
        hypothesis: "Encoded PowerShell commands run on endpoints",
        hunt_status: active,
        sigma_rule: ${JSON.stringify(HUNT_SIGMA_RULE)},
        native_queries: [{ platform: "splunk", language: "spl", query: ${JSON.stringify('index=edr CommandLine="* -enc *"')} }]
      }) { id }
    }
  `, 'Create the hunt');
  const huntId = hunt.huntAdd.id;
  const runs = await graphqlRequest<{ huntRunStart: Array<{ id: string }> }>(request, `
    mutation { huntRunStart(id: "${huntId}", input: { security_platform_ids: ["${securityPlatformId}"] }) { id } }
  `, 'Start the hunt run');
  const runId = runs.huntRunStart[0].id;
  await graphqlRequest(request, `
    mutation {
      huntRunReport(id: "${runId}", input: {
        status: completed, query_language: "spl", translated_query: ${JSON.stringify('index=edr CommandLine="* -enc *"')},
        hits_count: 3, distinct_entities: 1,
        evidence_sample: [{ field: "host.name", value_hash: "e2e-host", value_preview: "WS-E2E-01", count: 3 }]
      }) { id }
    }
  `, 'Report the hunt run completed');
  return { huntId, runId, connectorId, securityPlatformId };
};

export const deleteSeededHunt = async (request: APIRequestContext, seeded: SeededHunt) => {
  await graphqlRequest(request, `mutation { huntDelete(id: "${seeded.huntId}") }`, 'Delete the hunt');
  await graphqlRequest(request, `mutation { deleteConnector(id: "${seeded.connectorId}") }`, 'Delete the hunt connector');
  await graphqlRequest(request, `mutation { securityPlatformDelete(id: "${seeded.securityPlatformId}") }`, 'Delete the hunt security platform');
};

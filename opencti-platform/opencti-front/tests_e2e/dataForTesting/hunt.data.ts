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
export const seedHuntWithCompletedRun = async (
  request: APIRequestContext,
  name: string,
  labels?: { connector: string; securityPlatform: string },
): Promise<SeededHunt> => {
  const connectorId = uuid();
  await graphqlRequest(request, `
    mutation {
      registerConnector(input: {
        id: "${connectorId}", name: ${JSON.stringify(labels?.connector ?? `E2E hunt connector ${connectorId}`)},
        type: INTERNAL_HUNT, scope: ["splunk"], auto: false, only_contextual: false
      }) { id }
    }
  `, 'Register the hunt connector');
  const registration = await graphqlRequest<{ huntConnectorRegister: { securityPlatform: { id: string } } }>(request, `
    mutation {
      huntConnectorRegister(input: {
        connector_id: "${connectorId}", platform: "splunk", languages: ["spl"],
        security_platform_name: ${JSON.stringify(labels?.securityPlatform ?? `E2E Splunk ${connectorId}`)}
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
        hunt_scope: ${JSON.stringify(JSON.stringify({ mode: 'and', filters: [{ key: ['id'], values: [securityPlatformId], operator: 'eq', mode: 'or' }], filterGroups: [] }))},
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

/**
 * Starts one more run of a seeded hunt and reports it the way its hunt connector would.
 * `report` is the body of the HuntRunReportInput, for instance `status: failed, error: "..."`.
 */
export const startAndReportHuntRun = async (request: APIRequestContext, seeded: SeededHunt, report: string): Promise<string> => {
  const runs = await graphqlRequest<{ huntRunStart: Array<{ id: string }> }>(request, `
    mutation { huntRunStart(id: "${seeded.huntId}", input: { security_platform_ids: ["${seeded.securityPlatformId}"] }) { id } }
  `, 'Start the hunt run');
  const runId = runs.huntRunStart[0].id;
  await graphqlRequest(request, `mutation { huntRunReport(id: "${runId}", input: { ${report} }) { id } }`, 'Report the hunt run');
  return runId;
};

/**
 * Answers the latest translation preview of a hunt the way its hunt connector would, once the preview exists.
 */
export const answerLatestHuntPreview = async (request: APIRequestContext, huntId: string, translatedQuery: string): Promise<boolean> => {
  const runs = await graphqlRequest<{ huntRuns: { edges: Array<{ node: { id: string; hunt_run_status: string } }> } }>(request, `
    query {
      huntRuns(first: 1, orderBy: created_at, orderMode: desc, filters: {
        mode: and, filterGroups: [],
        filters: [
          { key: ["hunt_id"], values: ["${huntId}"], operator: eq, mode: or },
          { key: ["hunt_run_mode"], values: ["preview"], operator: eq, mode: or }
        ]
      }) { edges { node { id hunt_run_status } } }
    }
  `, 'Find the translation preview');
  const preview = runs.huntRuns.edges[0]?.node;
  if (!preview || preview.hunt_run_status !== 'queued') {
    return false;
  }
  await graphqlRequest(request, `
    mutation { huntRunReport(id: "${preview.id}", input: { status: completed, query_language: "spl", translated_query: ${JSON.stringify(translatedQuery)} }) { id } }
  `, 'Report the translation preview');
  return true;
};

export const deleteSeededHunt = async (request: APIRequestContext, seeded: SeededHunt) => {
  await graphqlRequest(request, `mutation { huntDelete(id: "${seeded.huntId}") }`, 'Delete the hunt');
  await graphqlRequest(request, `mutation { deleteConnector(id: "${seeded.connectorId}") }`, 'Delete the hunt connector');
  await graphqlRequest(request, `mutation { securityPlatformDelete(id: "${seeded.securityPlatformId}") }`, 'Delete the hunt security platform');
};

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
 * Records the verdict of an analyst on a completed run.
 */
export const setHuntRunVerdict = async (request: APIRequestContext, runId: string, verdict: string, feedback: string) => {
  await graphqlRequest(request, `
    mutation { huntRunSetVerdict(id: "${runId}", input: { verdict: ${verdict}, hunt_analyst_feedback: ${JSON.stringify(feedback)} }) { id } }
  `, 'Set the hunt run verdict');
};

/**
 * Answers a translation preview run the way its hunt connector would.
 */
export const answerHuntPreview = async (request: APIRequestContext, runId: string, translatedQuery: string) => {
  await graphqlRequest(request, `
    mutation { huntRunReport(id: "${runId}", input: { status: completed, query_language: "spl", translated_query: ${JSON.stringify(translatedQuery)} }) { id } }
  `, 'Report the translation preview');
};

/**
 * The translation preview of a hunt waiting for its hunt connector, for instance the translation check its activation
 * queued. Only for a hunt with a single preview run: the latest one is returned.
 */
export const findQueuedHuntPreview = async (request: APIRequestContext, huntId: string): Promise<string | undefined> => {
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
  return preview?.hunt_run_status === 'queued' ? preview.id : undefined;
};

/**
 * Creates a draft hunt the way the Hunt Planner proposes one: written by an agent, waiting for an analyst to review
 * and activate it.
 */
export const seedAgentDraftHunt = async (request: APIRequestContext, name: string): Promise<string> => {
  const hunt = await graphqlRequest<{ huntAdd: { id: string } }>(request, `
    mutation {
      huntAdd(input: {
        name: ${JSON.stringify(name)},
        hypothesis: "Encoded PowerShell commands run on endpoints",
        hunt_status: draft,
        hunt_source_kind: agent,
        sigma_rule: ${JSON.stringify(HUNT_SIGMA_RULE)}
      }) { id }
    }
  `, 'Create the draft hunt');
  return hunt.huntAdd.id;
};

export const deleteHunt = async (request: APIRequestContext, huntId: string) => {
  await graphqlRequest(request, `mutation { huntDelete(id: "${huntId}") }`, 'Delete the hunt');
};

export interface SeededHuntPlatform {
  connectorId: string;
  securityPlatformId: string;
}

/**
 * Registers a hunt connector the way the Splunk hunt connector does, looking up indicator values when asked.
 */
export const seedHuntPlatform = async (request: APIRequestContext, name: string, supportsIndicators = true): Promise<SeededHuntPlatform> => {
  const connectorId = uuid();
  await graphqlRequest(request, `
    mutation {
      registerConnector(input: {
        id: "${connectorId}", name: ${JSON.stringify(`${name} connector`)},
        type: INTERNAL_HUNT, scope: ["splunk"], auto: false, only_contextual: false
      }) { id }
    }
  `, 'Register the hunt connector');
  const registration = await graphqlRequest<{ huntConnectorRegister: { securityPlatform: { id: string } } }>(request, `
    mutation {
      huntConnectorRegister(input: {
        connector_id: "${connectorId}", platform: "splunk", languages: ["spl"],
        security_platform_name: ${JSON.stringify(name)}, supports_indicators: ${supportsIndicators}
      }) { securityPlatform { id } }
    }
  `, 'Register the hunt security platform');
  return { connectorId, securityPlatformId: registration.huntConnectorRegister.securityPlatform.id };
};

// The permissions the Splunk hunt connector declares at registration, as the connectors repository ships them
export const SPLUNK_HUNT_REQUIRED_PERMISSIONS = [
  { name: 'search', purpose: 'Capability: create the search jobs of the hunts, read their status and results, cancel and delete them.' },
  { name: 'Read on the app SPLUNK_HUNT_APP', purpose: 'The search jobs run in this app namespace (search by default).' },
  { name: 'srchIndexesAllowed', purpose: 'Every index the hunts must cover, for example wineventlog, sysmon or main.' },
  { name: 'edit_tokens_own', purpose: 'Optional: lets the account create its own authentication token.' },
];
export const SPLUNK_HUNT_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/hunt-connectors/#splunk';

/**
 * Registers a hunt connector declaring the permissions its account needs and its setup documentation, the way the
 * Splunk hunt connector does at startup.
 */
export const seedHuntConnectorWithSetup = async (request: APIRequestContext, name: string, securityPlatformName: string): Promise<SeededHuntPlatform> => {
  const connectorId = uuid();
  await graphqlRequest(request, `
    mutation {
      registerConnector(input: {
        id: "${connectorId}", name: ${JSON.stringify(name)},
        type: INTERNAL_HUNT, scope: ["splunk"], auto: false, only_contextual: false
      }) { id }
    }
  `, 'Register the hunt connector');
  const permissions = SPLUNK_HUNT_REQUIRED_PERMISSIONS.map((permission) => `{ name: ${JSON.stringify(permission.name)}, purpose: ${JSON.stringify(permission.purpose)} }`);
  const registration = await graphqlRequest<{ huntConnectorRegister: { securityPlatform: { id: string } } }>(request, `
    mutation {
      huntConnectorRegister(input: {
        connector_id: "${connectorId}", platform: "splunk", languages: ["spl"], supports_preview: true, supports_indicators: true,
        security_platform_name: ${JSON.stringify(securityPlatformName)},
        required_permissions: [${permissions.join(', ')}],
        documentation_url: ${JSON.stringify(SPLUNK_HUNT_DOCUMENTATION_URL)}
      }) { securityPlatform { id } }
    }
  `, 'Register the hunt security platform');
  return { connectorId, securityPlatformId: registration.huntConnectorRegister.securityPlatform.id };
};

/**
 * Tests the connection of a hunt connector and answers the test the way the connector does, one result per check.
 */
export const testHuntConnection = async (request: APIRequestContext, connectorId: string, checks: Array<{ name: string; ok: boolean; message: string }>) => {
  const requested = await graphqlRequest<{ huntConnectorTestConnection: { connection_check: { id: string } } }>(request, `
    mutation { huntConnectorTestConnection(id: "${connectorId}") { connection_check { id } } }
  `, 'Test the connection of the hunt connector');
  const checkId = requested.huntConnectorTestConnection.connection_check.id;
  const items = checks.map((check) => `{ name: ${JSON.stringify(check.name)}, ok: ${check.ok}, message: ${JSON.stringify(check.message)} }`);
  await graphqlRequest(request, `
    mutation {
      huntConnectorCheckReport(input: { connector_id: "${connectorId}", check_id: "${checkId}", checks: [${items.join(', ')}] }) {
        connection_check { status }
      }
    }
  `, 'Report the connection test of the hunt connector');
};

export const huntScopeOf = (securityPlatformId: string) => JSON.stringify({
  mode: 'and', filters: [{ key: ['id'], values: [securityPlatformId], operator: 'eq', mode: 'or' }], filterGroups: [],
});

/** Creates a draft hunt with no logic yet, scoped to one security platform. */
export const seedDraftHuntWithoutLogic = async (request: APIRequestContext, name: string, securityPlatformId: string): Promise<string> => {
  const hunt = await graphqlRequest<{ huntAdd: { id: string } }>(request, `
    mutation {
      huntAdd(input: {
        name: ${JSON.stringify(name)},
        hypothesis: "Encoded PowerShell commands run on endpoints",
        hunt_status: draft,
        hunt_scope: ${JSON.stringify(huntScopeOf(securityPlatformId))}
      }) { id }
    }
  `, 'Create the draft hunt');
  return hunt.huntAdd.id;
};

/**
 * Reports an indicator hunt run the way its hunt connector would: the values listed in `seen` are seen with their
 * hits and hosts, `unsearched` values are not searched, the others are not seen.
 */
export const reportIndicatorRun = async (
  request: APIRequestContext,
  runId: string,
  seen: Record<string, { hits: number; hosts: string[] }>,
  unsearched: string[] = [],
) => {
  const run = await graphqlRequest<{ huntRun: { ioc_results: Array<{ key: string; value: string }> } }>(request, `
    query { huntRun(id: "${runId}") { ioc_results { key value } } }
  `, 'Read the values of the run');
  const results = run.huntRun.ioc_results.map(({ key, value }) => {
    if (unsearched.includes(value)) {
      return `{ key: "${key}", searched: false, seen: false, reason: "File hashes are not indexed on this Splunk deployment" }`;
    }
    const found = seen[value];
    return found
      ? `{ key: "${key}", seen: true, hits_count: ${found.hits}, first_seen: "2026-10-03T08:12:00Z", last_seen: "2026-10-04T06:40:00Z", hosts: ${JSON.stringify(found.hosts)} }`
      : `{ key: "${key}", seen: false, hits_count: 0 }`;
  });
  await graphqlRequest(request, `
    mutation {
      huntRunReport(id: "${runId}", input: {
        status: completed, query_language: "spl", truncated: false, cost_ms: 3120,
        ioc_results: [${results.join(', ')}]
      }) { id }
    }
  `, 'Report the indicator hunt run');
};

export const deleteSeededHuntPlatform = async (request: APIRequestContext, seeded: SeededHuntPlatform) => {
  await graphqlRequest(request, `mutation { deleteConnector(id: "${seeded.connectorId}") }`, 'Delete the hunt connector');
  await graphqlRequest(request, `mutation { securityPlatformDelete(id: "${seeded.securityPlatformId}") }`, 'Delete the hunt security platform');
};

export const deleteSeededHunt = async (request: APIRequestContext, seeded: SeededHunt) => {
  await graphqlRequest(request, `mutation { huntDelete(id: "${seeded.huntId}") }`, 'Delete the hunt');
  await graphqlRequest(request, `mutation { deleteConnector(id: "${seeded.connectorId}") }`, 'Delete the hunt connector');
  await graphqlRequest(request, `mutation { securityPlatformDelete(id: "${seeded.securityPlatformId}") }`, 'Delete the hunt security platform');
};

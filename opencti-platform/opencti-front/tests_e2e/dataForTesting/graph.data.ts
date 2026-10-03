import { APIRequestContext, PlaywrightWorkerArgs } from '@playwright/test';
import { graphqlRequest } from './graphql.data';

const BASE_PATH = process.env.APP__BASE_PATH ?? '';
const AUTH_FILE = 'tests_e2e/.setup/.auth/user.json';

/**
 * An authenticated API context for `beforeAll` / `afterAll` hooks, which only receive worker
 * fixtures: the test-scoped `request` fixture is not available there.
 */
export const withApiRequest = async <T>(
  playwright: PlaywrightWorkerArgs['playwright'],
  run: (request: APIRequestContext) => Promise<T>,
): Promise<T> => {
  const context = await playwright.request.newContext({ baseURL: 'http://localhost:3000', storageState: AUTH_FILE });
  const prefixed = {
    post: (url: string, options?: Parameters<APIRequestContext['post']>[1]) => context.post(`${BASE_PATH}${url}`, options),
  } as APIRequestContext;
  try {
    return await run(prefixed);
  } finally {
    await context.dispose();
  }
};

/**
 * A small, fully known knowledge graph shared by the graph end-to-end tests:
 *
 *   Intrusion Set --uses (90)--> Malware --uses (15)--> Attack Pattern
 *        \___________________uses (60)___________________/
 *   Malware --communicates-with--> IPv4 address
 *
 * - the report contains every entity and relationship (knowledge graph);
 * - a second report shares the malware and the IPv4 address (correlation graph);
 * - an investigation starts from the three domain objects (investigation graph).
 *
 * Names carry a run suffix so concurrent or retried runs never collide.
 */
export interface GraphFixture {
  suffix: string;
  authorId: string;
  authorName: string;
  tlpGreenId: string;
  intrusionSet: { id: string; name: string };
  malware: { id: string; name: string };
  attackPattern: { id: string; name: string };
  ipv4: { id: string; value: string };
  domain: { id: string; value: string };
  relationships: { id: string; type: string; fromId: string; toId: string }[];
  report: { id: string; name: string };
  correlatedReport: { id: string; name: string };
  investigation: { id: string; name: string };
}

interface IdResult { id: string }

const quote = (value: string) => JSON.stringify(value);

const addDomainObject = async (
  request: APIRequestContext,
  mutation: 'intrusionSetAdd' | 'malwareAdd' | 'attackPatternAdd',
  name: string,
  extra: string,
) => {
  const data = await graphqlRequest<Record<string, IdResult>>(
    request,
    `mutation { ${mutation}(input: { name: ${quote(name)}${extra} }) { id } }`,
    `${mutation} ${name}`,
  );
  return data[mutation].id;
};

const addRelationship = async (
  request: APIRequestContext,
  input: { type: string; fromId: string; toId: string; confidence: number; createdBy: string; start: string; stop: string },
) => {
  const data = await graphqlRequest<{ stixCoreRelationshipAdd: IdResult }>(
    request,
    `mutation { stixCoreRelationshipAdd(input: {
      relationship_type: ${quote(input.type)},
      fromId: ${quote(input.fromId)},
      toId: ${quote(input.toId)},
      confidence: ${input.confidence},
      createdBy: ${quote(input.createdBy)},
      start_time: ${quote(input.start)},
      stop_time: ${quote(input.stop)}
    }) { id } }`,
    `relationship ${input.type}`,
  );
  return { id: data.stixCoreRelationshipAdd.id, type: input.type, fromId: input.fromId, toId: input.toId };
};

const addReport = async (request: APIRequestContext, name: string, objects: string[], createdBy: string) => {
  const data = await graphqlRequest<{ reportAdd: IdResult }>(
    request,
    `mutation { reportAdd(input: {
      name: ${quote(name)},
      published: ${quote(new Date('2025-06-01T00:00:00.000Z').toISOString())},
      createdBy: ${quote(createdBy)},
      objects: ${JSON.stringify(objects)}
    }) { id } }`,
    `report ${name}`,
  );
  return data.reportAdd.id;
};

/**
 * @param fixedSuffix A constant suffix gives constant names and values, which visual snapshots
 * need; the platform deduplicates by name, so a second run reuses the same entities.
 */
export const createGraphFixture = async (request: APIRequestContext, fixedSuffix?: string): Promise<GraphFixture> => {
  const suffix = fixedSuffix ?? `${Date.now().toString(36)}${Math.floor(Math.random() * 1000)}`;

  const markings = await graphqlRequest<{ markingDefinitions: { edges: { node: { id: string; definition: string } }[] } }>(
    request,
    'query { markingDefinitions(first: 50) { edges { node { id definition } } } }',
    'marking definitions',
  );
  const tlpGreen = markings.markingDefinitions.edges.find(({ node }) => node.definition === 'TLP:GREEN');
  if (!tlpGreen) throw new Error('TLP:GREEN marking definition not found');

  const authorName = `Graph author ${suffix}`;
  const author = await graphqlRequest<{ organizationAdd: IdResult }>(
    request,
    `mutation { organizationAdd(input: { name: ${quote(authorName)} }) { id } }`,
    'author',
  );
  const authorId = author.organizationAdd.id;

  const intrusionSetName = `Graph intrusion set ${suffix}`;
  const malwareName = `Graph malware ${suffix}`;
  const attackPatternName = `Graph attack pattern ${suffix}`;
  const intrusionSetId = await addDomainObject(
    request,
    'intrusionSetAdd',
    intrusionSetName,
    `, createdBy: ${quote(authorId)}, objectMarking: [${quote(tlpGreen.node.id)}], confidence: 90`,
  );
  const malwareId = await addDomainObject(request, 'malwareAdd', malwareName, `, createdBy: ${quote(authorId)}, confidence: 75`);
  const attackPatternId = await addDomainObject(request, 'attackPatternAdd', attackPatternName, ', confidence: 40');

  // TEST-NET-2 (RFC 5737), never routable.
  const ipv4Value = fixedSuffix ? '198.51.100.250' : `198.51.100.${(Date.now() % 200) + 20}`;
  const ipv4 = await graphqlRequest<{ stixCyberObservableAdd: IdResult }>(
    request,
    `mutation { stixCyberObservableAdd(type: "IPv4-Addr", IPv4Addr: { value: ${quote(ipv4Value)} }) { id } }`,
    'ipv4',
  );
  const ipv4Id = ipv4.stixCyberObservableAdd.id;
  // A domain name can carry a nested "resolves to" reference towards the IPv4 address.
  const domainValue = `graph-${suffix}.example.com`;
  const domain = await graphqlRequest<{ stixCyberObservableAdd: IdResult }>(
    request,
    `mutation { stixCyberObservableAdd(type: "Domain-Name", DomainName: { value: ${quote(domainValue)} }) { id } }`,
    'domain name',
  );
  const domainId = domain.stixCyberObservableAdd.id;

  const relationships = [
    await addRelationship(request, {
      type: 'uses', fromId: intrusionSetId, toId: malwareId, confidence: 90, createdBy: authorId, start: '2024-01-01T00:00:00.000Z', stop: '2024-06-01T00:00:00.000Z',
    }),
    await addRelationship(request, {
      type: 'uses', fromId: malwareId, toId: attackPatternId, confidence: 15, createdBy: authorId, start: '2024-03-01T00:00:00.000Z', stop: '2024-09-01T00:00:00.000Z',
    }),
    await addRelationship(request, {
      type: 'uses', fromId: intrusionSetId, toId: attackPatternId, confidence: 60, createdBy: authorId, start: '2025-01-01T00:00:00.000Z', stop: '2025-03-01T00:00:00.000Z',
    }),
    await addRelationship(request, {
      type: 'communicates-with', fromId: malwareId, toId: ipv4Id, confidence: 70, createdBy: authorId, start: '2025-02-01T00:00:00.000Z', stop: '2025-04-01T00:00:00.000Z',
    }),
  ];

  const reportName = `Graph report ${suffix}`;
  const reportId = await addReport(
    request,
    reportName,
    [intrusionSetId, malwareId, attackPatternId, ipv4Id, domainId, ...relationships.map((r) => r.id)],
    authorId,
  );
  const correlatedReportName = `Graph correlated report ${suffix}`;
  const correlatedReportId = await addReport(request, correlatedReportName, [malwareId, ipv4Id], authorId);

  const investigationName = `Graph investigation ${suffix}`;
  const investigation = await graphqlRequest<{ workspaceAdd: IdResult }>(
    request,
    `mutation { workspaceAdd(input: {
      type: "investigation",
      name: ${quote(investigationName)},
      investigated_entities_ids: ${JSON.stringify([intrusionSetId, malwareId, attackPatternId])}
    }) { id } }`,
    'investigation',
  );

  return {
    suffix,
    authorId,
    authorName,
    tlpGreenId: tlpGreen.node.id,
    intrusionSet: { id: intrusionSetId, name: intrusionSetName },
    malware: { id: malwareId, name: malwareName },
    attackPattern: { id: attackPatternId, name: attackPatternName },
    ipv4: { id: ipv4Id, value: ipv4Value },
    domain: { id: domainId, value: domainValue },
    relationships,
    report: { id: reportId, name: reportName },
    correlatedReport: { id: correlatedReportId, name: correlatedReportName },
    investigation: { id: investigation.workspaceAdd.id, name: investigationName },
  };
};

const deleteSilently = async (request: APIRequestContext, query: string) => {
  try {
    await graphqlRequest(request, query, 'cleanup');
  } catch {
    // Already removed by the test itself (removal capability) or by a cascade.
  }
};

/** Removes an investigation a test created from the graph. */
export const deleteInvestigation = (request: APIRequestContext, id: string) => deleteSilently(request, `mutation { workspaceDelete(id: ${quote(id)}) }`);

export const deleteGraphFixture = async (request: APIRequestContext, fixture: GraphFixture | undefined) => {
  if (!fixture) return;
  await deleteSilently(request, `mutation { workspaceDelete(id: ${quote(fixture.investigation.id)}) }`);
  for (const relationship of fixture.relationships) {
    await deleteSilently(request, `mutation { stixCoreRelationshipEdit(id: ${quote(relationship.id)}) { delete } }`);
  }
  const ids = [
    fixture.report.id,
    fixture.correlatedReport.id,
    fixture.intrusionSet.id,
    fixture.malware.id,
    fixture.attackPattern.id,
    fixture.ipv4.id,
    fixture.domain.id,
    fixture.authorId,
  ];
  for (const id of ids) {
    // Sequential on purpose: the platform serializes deletions of linked elements.
    await deleteSilently(request, `mutation { stixCoreObjectEdit(id: ${quote(id)}) { delete } }`);
  }
};

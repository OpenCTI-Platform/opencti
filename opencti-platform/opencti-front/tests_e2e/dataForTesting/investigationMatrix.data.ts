import { APIRequestContext } from '@playwright/test';
import { graphqlRequest } from './graphql.data';

/** Kill chain of the seeded techniques. Its phase holds every seeded attack pattern. */
export const E2E_KILL_CHAIN = 'mitre-attack';
/** A second kill chain with many phases, hence a matrix much wider than a small viewport. Only the unrelated technique sits in it. */
export const E2E_WIDE_KILL_CHAIN = 'e2e-wide-chain';
const WIDE_KILL_CHAIN_PHASE_COUNT = 8;

export type SeededTechniqueKey = 'T9001' | 'T9002' | 'T9003' | 'T9003.001';

export interface InvestigationMatrixSeed {
  investigationId: string;
  investigationName: string;
  attackPatterns: Record<SeededTechniqueKey, string>;
  intrusionSets: Record<'A' | 'B', string>;
  /** Security platform with a `should-cover` relationship to T9001 only. */
  securityPlatformId: string;
  /**
   * Technique T9004 "E2E Unrelated": in every seeded kill chain but never in an investigation.
   * It is the "unrelated platform technique" of the highlight tests.
   */
  unrelatedAttackPatternId: string;
  /** Report "E2E Matrix report", which contains T9001. It is in the investigation too. */
  reportId: string;
}

const quote = (value: string) => JSON.stringify(value);

const addKillChainPhase = async (request: APIRequestContext, killChainName: string, phaseName: string, order: number): Promise<string> => {
  const data = await graphqlRequest<{ killChainPhaseAdd: { id: string } }>(request, `
    mutation {
      killChainPhaseAdd(input: {
        kill_chain_name: ${quote(killChainName)},
        phase_name: ${quote(phaseName)},
        x_opencti_order: ${order}
      }) { id }
    }
  `, `Create kill chain phase ${killChainName}/${phaseName}`);
  return data.killChainPhaseAdd.id;
};

const addAttackPattern = async (request: APIRequestContext, name: string, mitreId: string, phaseIds: string[]): Promise<string> => {
  const data = await graphqlRequest<{ attackPatternAdd: { id: string } }>(request, `
    mutation {
      attackPatternAdd(input: {
        name: ${quote(name)},
        x_mitre_id: ${quote(mitreId)},
        killChainPhases: [${phaseIds.map(quote).join(', ')}]
      }) { id }
    }
  `, `Create attack pattern ${mitreId}`);
  return data.attackPatternAdd.id;
};

const addIntrusionSet = async (request: APIRequestContext, name: string): Promise<string> => {
  const data = await graphqlRequest<{ intrusionSetAdd: { id: string } }>(request, `
    mutation {
      intrusionSetAdd(input: { name: ${quote(name)} }) { id }
    }
  `, `Create intrusion set ${name}`);
  return data.intrusionSetAdd.id;
};

const addSecurityPlatform = async (request: APIRequestContext, name: string): Promise<string> => {
  const data = await graphqlRequest<{ securityPlatformAdd: { id: string } }>(request, `
    mutation {
      securityPlatformAdd(input: { name: ${quote(name)} }) { id }
    }
  `, `Create security platform ${name}`);
  return data.securityPlatformAdd.id;
};

interface RelationExtra {
  start_time?: string;
  createdBy?: string;
  objectMarking?: string[];
}

const addRelation = async (request: APIRequestContext, type: string, fromId: string, toId: string, extra: RelationExtra = {}): Promise<string> => {
  const data = await graphqlRequest<{ stixCoreRelationshipAdd: { id: string } }>(request, `
    mutation {
      stixCoreRelationshipAdd(input: {
        relationship_type: ${quote(type)},
        fromId: ${quote(fromId)},
        toId: ${quote(toId)}${extra.start_time ? `,
        start_time: ${quote(extra.start_time)}` : ''}${extra.createdBy ? `,
        createdBy: ${quote(extra.createdBy)}` : ''}${extra.objectMarking ? `,
        objectMarking: [${extra.objectMarking.map(quote).join(', ')}]` : ''}
      }) { id }
    }
  `, `Create ${type} relationship`);
  return data.stixCoreRelationshipAdd.id;
};

/** A report that contains the given objects. Its `object` relationships are what the container scoring rule reads. */
const addReport = async (request: APIRequestContext, name: string, objectIds: string[]): Promise<string> => {
  const data = await graphqlRequest<{ reportAdd: { id: string } }>(request, `
    mutation {
      reportAdd(input: {
        name: ${quote(name)},
        published: "2026-01-01T00:00:00.000Z",
        objects: [${objectIds.map(quote).join(', ')}]
      }) { id }
    }
  `, `Create report ${name}`);
  return data.reportAdd.id;
};

/** The id of the `object` relationship from a container to one of its objects. */
const getContainsRelationId = async (request: APIRequestContext, containerId: string, objectId: string): Promise<string> => {
  const data = await graphqlRequest<{ stixRefRelationships: { edges: { node: { id: string } }[] } }>(request, `
    query {
      stixRefRelationships(fromId: ${quote(containerId)}, toId: ${quote(objectId)}, relationship_type: ["object"], first: 1) {
        edges { node { id } }
      }
    }
  `, `Read the object relationship of report ${containerId}`);
  const relation = data.stixRefRelationships.edges[0];
  if (!relation) throw new Error(`Report ${containerId} does not contain ${objectId}`);
  return relation.node.id;
};

const addOrganization = async (request: APIRequestContext, name: string): Promise<string> => {
  const data = await graphqlRequest<{ organizationAdd: { id: string } }>(request, `
    mutation {
      organizationAdd(input: { name: ${quote(name)} }) { id }
    }
  `, `Create organization ${name}`);
  return data.organizationAdd.id;
};

/** The id of a marking definition the platform ships with, such as `TLP:GREEN`. */
const getMarkingId = async (request: APIRequestContext, definition: string): Promise<string> => {
  // Filtered on the server: a client-side search of a first page could miss it among many markings.
  const data = await graphqlRequest<{ markingDefinitions: { edges: { node: { id: string; definition: string } }[] } }>(request, `
    query {
      markingDefinitions(
        first: 1
        filters: { mode: and, filters: [{ key: "definition", values: [${quote(definition)}], operator: eq }], filterGroups: [] }
      ) { edges { node { id definition } } }
    }
  `, `Read the marking definition ${definition}`);
  const marking = data.markingDefinitions.edges[0];
  if (!marking) throw new Error(`Marking definition ${definition} not found`);
  return marking.node.id;
};

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** Midnight UTC, `days` ago: the same value all day, so that seeding twice upserts the same relationship. */
const daysAgo = (days: number): string => {
  const midnight = Math.floor((Date.now() - days * MS_PER_DAY) / MS_PER_DAY) * MS_PER_DAY;
  return new Date(midnight).toISOString();
};

/**
 * The knowledge of the filter scenarios, which come on top of A and B:
 * - intrusion set C uses `attackPatternId` since 30 days, under `TLP:GREEN`, authored by `E2E Matrix author one`
 * - intrusion set D uses it since 400 days, under `TLP:AMBER`, authored by `E2E Matrix author two`
 * The marking and the author are those of the `uses` relationship, which the marking and author filters read.
 * Returns the ids the investigation holds: both intrusion sets and both relationships.
 */
const seedFilterKnowledge = async (request: APIRequestContext, attackPatternId: string): Promise<string[]> => {
  const [greenId, amberId] = [await getMarkingId(request, 'TLP:GREEN'), await getMarkingId(request, 'TLP:AMBER')];
  const [authorOneId, authorTwoId] = [
    await addOrganization(request, 'E2E Matrix author one'),
    await addOrganization(request, 'E2E Matrix author two'),
  ];
  const intrusionSetCId = await addIntrusionSet(request, 'E2E Matrix IS C');
  const intrusionSetDId = await addIntrusionSet(request, 'E2E Matrix IS D');
  const relationCId = await addRelation(request, 'uses', intrusionSetCId, attackPatternId, {
    start_time: daysAgo(30),
    createdBy: authorOneId,
    objectMarking: [greenId],
  });
  const relationDId = await addRelation(request, 'uses', intrusionSetDId, attackPatternId, {
    start_time: daysAgo(400),
    createdBy: authorTwoId,
    objectMarking: [amberId],
  });
  return [intrusionSetCId, intrusionSetDId, relationCId, relationDId];
};

const addInvestigation = async (request: APIRequestContext, name: string, entityIds: string[]): Promise<string> => {
  const data = await graphqlRequest<{ workspaceAdd: { id: string } }>(request, `
    mutation {
      workspaceAdd(input: {
        type: "investigation",
        name: ${quote(name)},
        investigated_entities_ids: [${entityIds.map(quote).join(', ')}]
      }) { id }
    }
  `, `Create investigation ${name}`);
  return data.workspaceAdd.id;
};

/** Removes a seeded investigation. The seeded knowledge entities are idempotent upserts and stay. */
export const deleteInvestigation = async (request: APIRequestContext, id: string): Promise<void> => {
  await graphqlRequest<{ workspaceDelete: string }>(request, `
    mutation {
      workspaceDelete(id: ${quote(id)})
    }
  `, `Delete investigation ${id}`);
};

interface SeededKnowledge {
  attackPatterns: InvestigationMatrixSeed['attackPatterns'];
  intrusionSets: InvestigationMatrixSeed['intrusionSets'];
  securityPlatformId: string;
  unrelatedAttackPatternId: string;
  subtechniqueRelationId: string;
  /** `uses` relationships: A uses T9001, B uses T9001, A uses T9002. */
  usesRelationIds: string[];
}

/**
 * Upserts the knowledge of the matrix scenarios:
 * - attack patterns T9001, T9002, T9003 and its sub-technique T9003.001 in `mitre-attack`/`e2e-execution`
 * - T9004, in every seeded kill chain and in no investigation
 * - intrusion sets A and B: A uses T9001 and T9002, B uses T9001
 * - a security platform that should cover T9001
 * Entities are upserted by their standard id, so seeding twice is harmless.
 */
const seedKnowledge = async (request: APIRequestContext): Promise<SeededKnowledge> => {
  const executionPhaseId = await addKillChainPhase(request, E2E_KILL_CHAIN, 'e2e-execution', 1);
  const widePhaseIds: string[] = [];
  for (let order = 1; order <= WIDE_KILL_CHAIN_PHASE_COUNT; order += 1) {
    widePhaseIds.push(await addKillChainPhase(request, E2E_WIDE_KILL_CHAIN, `e2e-wide-${order}`, order));
  }

  const alphaId = await addAttackPattern(request, 'E2E Alpha', 'T9001', [executionPhaseId]);
  const betaId = await addAttackPattern(request, 'E2E Beta', 'T9002', [executionPhaseId]);
  const gammaId = await addAttackPattern(request, 'E2E Gamma', 'T9003', [executionPhaseId]);
  const gammaSubId = await addAttackPattern(request, 'E2E Gamma sub', 'T9003.001', [executionPhaseId]);
  const unrelatedId = await addAttackPattern(request, 'E2E Unrelated', 'T9004', [executionPhaseId, ...widePhaseIds]);
  const subtechniqueRelationId = await addRelation(request, 'subtechnique-of', gammaSubId, gammaId);

  const intrusionSetAId = await addIntrusionSet(request, 'E2E Matrix A');
  const intrusionSetBId = await addIntrusionSet(request, 'E2E Matrix B');
  const usesRelationIds = [
    await addRelation(request, 'uses', intrusionSetAId, alphaId),
    await addRelation(request, 'uses', intrusionSetBId, alphaId),
    await addRelation(request, 'uses', intrusionSetAId, betaId),
  ];

  const securityPlatformId = await addSecurityPlatform(request, 'E2E Matrix platform');
  await addRelation(request, 'should-cover', securityPlatformId, alphaId);

  return {
    attackPatterns: { T9001: alphaId, T9002: betaId, T9003: gammaId, 'T9003.001': gammaSubId },
    intrusionSets: { A: intrusionSetAId, B: intrusionSetBId },
    securityPlatformId,
    unrelatedAttackPatternId: unrelatedId,
    subtechniqueRelationId,
    usesRelationIds,
  };
};

/**
 * Seeds the knowledge of the matrix scenarios and an investigation holding it.
 * The investigation also holds report "E2E Matrix report", which contains T9001, and that `object` relationship:
 * the container scoring rule reads it from the real query.
 * Scores: T9001 = 3 (A, B and the report), T9002 = 1 (A), T9003 unscored. T9003.001 is in the investigation too, unscored.
 * With `withFilterData`, the investigation also holds intrusion sets C and D, which use T9001 under another date,
 * marking and author each (see `seedFilterKnowledge`): T9001 then scores 5.
 * Each call creates a new investigation.
 */
export const seedInvestigationMatrix = async (
  request: APIRequestContext,
  { withFilterData = false }: { withFilterData?: boolean } = {},
): Promise<InvestigationMatrixSeed> => {
  const knowledge = await seedKnowledge(request);
  const { attackPatterns, intrusionSets } = knowledge;
  const filterIds = withFilterData ? await seedFilterKnowledge(request, attackPatterns.T9001) : [];
  const reportId = await addReport(request, 'E2E Matrix report', [attackPatterns.T9001]);
  const reportContainsRelationId = await getContainsRelationId(request, reportId, attackPatterns.T9001);

  const investigationName = `E2E matrix ${Date.now()}`;
  const investigationId = await addInvestigation(request, investigationName, [
    attackPatterns.T9001,
    attackPatterns.T9002,
    attackPatterns.T9003,
    attackPatterns['T9003.001'],
    intrusionSets.A,
    intrusionSets.B,
    knowledge.subtechniqueRelationId,
    ...knowledge.usesRelationIds,
    reportId,
    reportContainsRelationId,
    ...filterIds,
  ]);

  return {
    investigationId,
    investigationName,
    attackPatterns,
    intrusionSets,
    securityPlatformId: knowledge.securityPlatformId,
    unrelatedAttackPatternId: knowledge.unrelatedAttackPatternId,
    reportId,
  };
};

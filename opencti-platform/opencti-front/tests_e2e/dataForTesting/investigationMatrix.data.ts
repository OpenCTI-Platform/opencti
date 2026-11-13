import { APIRequestContext } from '@playwright/test';
import { graphqlRequest } from './graphql.data';

/** Kill chain of the seeded techniques. Its phase holds every seeded attack pattern. */
export const E2E_KILL_CHAIN = 'mitre-attack';
/** A second kill chain holding only the unrelated technique: switching to it leaves the investigation's attack patterns unplaced. */
export const E2E_OTHER_KILL_CHAIN = 'e2e-other-chain';
/** A third kill chain with many phases, hence a matrix much wider than a small viewport. Only the unrelated technique sits in it. */
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

const addRelation = async (request: APIRequestContext, type: string, fromId: string, toId: string): Promise<string> => {
  const data = await graphqlRequest<{ stixCoreRelationshipAdd: { id: string } }>(request, `
    mutation {
      stixCoreRelationshipAdd(input: {
        relationship_type: ${quote(type)},
        fromId: ${quote(fromId)},
        toId: ${quote(toId)}
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
  /** A uses T9003.001. In no investigation unless a seed asks for it. */
  subtechniqueUseRelationId: string;
}

/**
 * Upserts the knowledge of the matrix scenarios:
 * - attack patterns T9001, T9002, T9003 and its sub-technique T9003.001 in `mitre-attack`/`e2e-execution`
 * - T9004, in every seeded kill chain and in no investigation
 * - intrusion sets A and B: A uses T9001, T9002 and T9003.001, B uses T9001
 * - a security platform that should cover T9001
 * Entities are upserted by their standard id, so seeding twice is harmless.
 */
const seedKnowledge = async (request: APIRequestContext): Promise<SeededKnowledge> => {
  const executionPhaseId = await addKillChainPhase(request, E2E_KILL_CHAIN, 'e2e-execution', 1);
  const otherPhaseId = await addKillChainPhase(request, E2E_OTHER_KILL_CHAIN, 'e2e-other', 1);
  const widePhaseIds: string[] = [];
  for (let order = 1; order <= WIDE_KILL_CHAIN_PHASE_COUNT; order += 1) {
    widePhaseIds.push(await addKillChainPhase(request, E2E_WIDE_KILL_CHAIN, `e2e-wide-${order}`, order));
  }

  const alphaId = await addAttackPattern(request, 'E2E Alpha', 'T9001', [executionPhaseId]);
  const betaId = await addAttackPattern(request, 'E2E Beta', 'T9002', [executionPhaseId]);
  const gammaId = await addAttackPattern(request, 'E2E Gamma', 'T9003', [executionPhaseId]);
  const gammaSubId = await addAttackPattern(request, 'E2E Gamma sub', 'T9003.001', [executionPhaseId]);
  const unrelatedId = await addAttackPattern(request, 'E2E Unrelated', 'T9004', [executionPhaseId, otherPhaseId, ...widePhaseIds]);
  const subtechniqueRelationId = await addRelation(request, 'subtechnique-of', gammaSubId, gammaId);

  const intrusionSetAId = await addIntrusionSet(request, 'E2E Matrix A');
  const intrusionSetBId = await addIntrusionSet(request, 'E2E Matrix B');
  const usesRelationIds = [
    await addRelation(request, 'uses', intrusionSetAId, alphaId),
    await addRelation(request, 'uses', intrusionSetBId, alphaId),
    await addRelation(request, 'uses', intrusionSetAId, betaId),
  ];
  const subtechniqueUseRelationId = await addRelation(request, 'uses', intrusionSetAId, gammaSubId);

  const securityPlatformId = await addSecurityPlatform(request, 'E2E Matrix platform');
  await addRelation(request, 'should-cover', securityPlatformId, alphaId);

  return {
    attackPatterns: { T9001: alphaId, T9002: betaId, T9003: gammaId, 'T9003.001': gammaSubId },
    intrusionSets: { A: intrusionSetAId, B: intrusionSetBId },
    securityPlatformId,
    unrelatedAttackPatternId: unrelatedId,
    subtechniqueRelationId,
    usesRelationIds,
    subtechniqueUseRelationId,
  };
};

/**
 * Seeds the knowledge of the matrix scenarios and an investigation holding it.
 * Scores: T9001 = 2 (A and B), T9002 = 1 (A), T9003 unscored. T9003.001 is in the investigation too, unscored.
 * With `withSubtechniqueUse`, the investigation also holds `A uses T9003.001`: T9003.001 scores 1 and T9003 stays unscored.
 * With `withReport`, the investigation also holds the report that contains T9002, and that `object` relationship:
 * T9002 scores 2 (A and the report).
 * Each call creates a new investigation.
 */
export const seedInvestigationMatrix = async (
  request: APIRequestContext,
  { withSubtechniqueUse = false, withReport = false }: { withSubtechniqueUse?: boolean; withReport?: boolean } = {},
): Promise<InvestigationMatrixSeed> => {
  const knowledge = await seedKnowledge(request);
  const { attackPatterns, intrusionSets } = knowledge;
  // Report "E2E Matrix report" contains T9002. Seeded only on demand, so other scenarios see no report.
  const reportIds: string[] = [];
  if (withReport) {
    const reportId = await addReport(request, 'E2E Matrix report', [attackPatterns.T9002]);
    reportIds.push(reportId, await getContainsRelationId(request, reportId, attackPatterns.T9002));
  }

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
    ...(withSubtechniqueUse ? [knowledge.subtechniqueUseRelationId] : []),
    ...reportIds,
  ]);

  return {
    investigationId,
    investigationName,
    attackPatterns,
    intrusionSets,
    securityPlatformId: knowledge.securityPlatformId,
    unrelatedAttackPatternId: knowledge.unrelatedAttackPatternId,
  };
};

/** An investigation that holds attack patterns, with no entity linked to any of them: nothing is scored. */
export const seedInvestigationWithoutScores = async (request: APIRequestContext): Promise<string> => {
  const { attackPatterns } = await seedKnowledge(request);
  return addInvestigation(request, `E2E matrix unscored ${Date.now()}`, [attackPatterns.T9001, attackPatterns.T9002]);
};

/** An investigation that holds a single intrusion set and no attack pattern. */
export const seedInvestigationWithoutAttackPatterns = async (request: APIRequestContext): Promise<string> => {
  const intrusionSetId = await addIntrusionSet(request, 'E2E Matrix A');
  return addInvestigation(request, `E2E matrix empty ${Date.now()}`, [intrusionSetId]);
};

import { APIRequestContext } from '@playwright/test';
import { graphqlRequest } from './graphql.data';

/** Kill chain of the seeded techniques. Its phase holds every seeded attack pattern. */
export const E2E_KILL_CHAIN = 'mitre-attack';
/** A second kill chain holding only the unrelated technique: switching to it leaves the investigation's attack patterns unplaced. */
export const E2E_OTHER_KILL_CHAIN = 'e2e-other-chain';

export type SeededTechniqueKey = 'T9001' | 'T9002' | 'T9003' | 'T9003.001';

export interface InvestigationMatrixSeed {
  investigationId: string;
  attackPatterns: Record<SeededTechniqueKey, string>;
  intrusionSets: Record<'A' | 'B', string>;
  /** Security platform with a `should-cover` relationship to T9001 only. */
  securityPlatformId: string;
  /**
   * Technique T9004 "E2E Unrelated": in both seeded kill chains but never in the investigation.
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

/**
 * Seeds the knowledge of the US.1 scenarios and an investigation holding it:
 * - attack patterns T9001, T9002, T9003 and its sub-technique T9003.001 in `mitre-attack`/`e2e-execution`
 * - intrusion sets A and B: A uses T9001 and T9002, B uses T9001
 * - a security platform that should cover T9001
 * - T9004, an attack pattern left out of the investigation
 * Entities are upserted by their standard id, so seeding twice is harmless. Each call creates a new investigation.
 */
export const seedInvestigationMatrix = async (request: APIRequestContext): Promise<InvestigationMatrixSeed> => {
  const executionPhaseId = await addKillChainPhase(request, E2E_KILL_CHAIN, 'e2e-execution', 1);
  const otherPhaseId = await addKillChainPhase(request, E2E_OTHER_KILL_CHAIN, 'e2e-other', 1);

  const alphaId = await addAttackPattern(request, 'E2E Alpha', 'T9001', [executionPhaseId]);
  const betaId = await addAttackPattern(request, 'E2E Beta', 'T9002', [executionPhaseId]);
  const gammaId = await addAttackPattern(request, 'E2E Gamma', 'T9003', [executionPhaseId]);
  const gammaSubId = await addAttackPattern(request, 'E2E Gamma sub', 'T9003.001', [executionPhaseId]);
  const unrelatedId = await addAttackPattern(request, 'E2E Unrelated', 'T9004', [executionPhaseId, otherPhaseId]);
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

  const investigationId = await addInvestigation(request, `E2E matrix ${Date.now()}`, [
    alphaId,
    betaId,
    gammaId,
    gammaSubId,
    intrusionSetAId,
    intrusionSetBId,
    subtechniqueRelationId,
    ...usesRelationIds,
  ]);

  return {
    investigationId,
    attackPatterns: { T9001: alphaId, T9002: betaId, T9003: gammaId, 'T9003.001': gammaSubId },
    intrusionSets: { A: intrusionSetAId, B: intrusionSetBId },
    securityPlatformId,
    unrelatedAttackPatternId: unrelatedId,
  };
};

/** An investigation that holds a single intrusion set and no attack pattern. */
export const seedInvestigationWithoutAttackPatterns = async (request: APIRequestContext): Promise<string> => {
  const intrusionSetId = await addIntrusionSet(request, 'E2E Matrix A');
  return addInvestigation(request, `E2E matrix empty ${Date.now()}`, [intrusionSetId]);
};

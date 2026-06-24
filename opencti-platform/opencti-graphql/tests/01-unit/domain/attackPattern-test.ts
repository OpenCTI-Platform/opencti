import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import { getAttackPatternsMatrix } from '../../../src/domain/attackPattern';
import { RELATION_SUBTECHNIQUE_OF } from '../../../src/schema/stixCoreRelationship';
import { RELATION_KILL_CHAIN_PHASE } from '../../../src/schema/stixRefRelationship';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { BasicStoreEntity, BasicStoreRelation } from '../../../src/types/store';

// Helper to build a mock attack pattern.
// `subTechniqueIds` mimics the in-DB ref field that signals a parent has sub-techniques.
const buildAttackPattern = (
  id: string,
  name: string,
  killChainIds: string[],
  xMitreId?: string,
  description?: string,
  subTechniqueIds?: string[],
) => ({
  id,
  name,
  description: description ?? `Description of ${name}`,
  x_mitre_id: xMitreId,
  [RELATION_KILL_CHAIN_PHASE]: killChainIds,
  ...(subTechniqueIds ? { [RELATION_SUBTECHNIQUE_OF]: subTechniqueIds } : {}),
} as unknown as BasicStoreEntity);

// Helper to build a mock kill chain phase
const buildKillChainPhase = (
  id: string,
  killChainName: string,
  phaseName: string,
  order: number,
) => ({
  id,
  kill_chain_name: killChainName,
  phase_name: phaseName,
  x_opencti_order: order,
} as unknown as BasicStoreEntity);

// Helper to build a subtechnique-of relation
const buildSubTechniqueRelation = (fromId: string, toId: string) => ({
  fromId,
  toId,
} as BasicStoreRelation);

describe('Function getAttackPatternsMatrix()', () => {
  const mockData = (
    attackPatterns: BasicStoreEntity[],
    killChainPhases: BasicStoreEntity[],
    relations: BasicStoreRelation[],
  ) => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce(attackPatterns) // attack patterns
      .mockResolvedValueOnce(killChainPhases); // kill chain phases
    vi.spyOn(middlewareLoader, 'fullRelationsList')
      .mockResolvedValueOnce(relations);
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('normal use cases', () => {
    it('should return an empty matrix when there are no attack patterns', async () => {
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'initial-access', 1);
      mockData([], [phase], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result.attackPatternsOfPhases).toHaveLength(0);
    });

    it('should return an empty matrix when there are no kill chain phases', async () => {
      const ap = buildAttackPattern('ap-1', 'Phishing', ['phase-1']);
      mockData([ap], [], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result.attackPatternsOfPhases).toHaveLength(0);
    });

    it('should return phases with their attack patterns', async () => {
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'initial-access', 1);
      const ap1 = buildAttackPattern('ap-1', 'Phishing', ['phase-1'], 'T1566');
      const ap2 = buildAttackPattern('ap-2', 'Drive-by Compromise', ['phase-1'], 'T1189');
      mockData([ap1, ap2], [phase], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result.attackPatternsOfPhases).toHaveLength(1);
      const phaseResult = result.attackPatternsOfPhases[0];
      expect(phaseResult.kill_chain_id).toBe('phase-1');
      expect(phaseResult.kill_chain_name).toBe('mitre-attack');
      expect(phaseResult.phase_name).toBe('initial-access');
      expect(phaseResult.x_opencti_order).toBe(1);
      expect(phaseResult.attackPatterns).toHaveLength(2);
    });

    it('should include correct fields for each attack pattern in the matrix', async () => {
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'execution', 2);
      const ap = buildAttackPattern('ap-1', 'Command and Scripting Interpreter', ['phase-1'], 'T1059', 'Adversaries may abuse command interpreters.');
      mockData([ap], [phase], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      const attackPattern = result.attackPatternsOfPhases[0].attackPatterns[0];
      expect(attackPattern.attack_pattern_id).toBe('ap-1');
      expect(attackPattern.name).toBe('Command and Scripting Interpreter');
      expect(attackPattern.description).toBe('Adversaries may abuse command interpreters.');
      expect(attackPattern.x_mitre_id).toBe('T1059');
      expect(attackPattern.subAttackPatterns).toEqual([]);
      expect(attackPattern.subAttackPatternsSearchText).toBe('');
    });

    it('should attach sub-techniques to their parent attack patterns', async () => {
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'execution', 2);
      // Parent has the in-DB subtechnique-of ref field to mark it as a parent
      const parent = buildAttackPattern('ap-parent', 'Command and Scripting Interpreter', ['phase-1'], 'T1059', undefined, ['ap-sub']);
      // Sub-technique also references the kill chain phase
      const sub = buildAttackPattern('ap-sub', 'PowerShell', ['phase-1'], 'T1059.001', 'Adversaries may abuse PowerShell.');
      // ap-sub is a sub-technique of ap-parent: fromId=ap-sub, toId=ap-parent
      const subRel = buildSubTechniqueRelation('ap-sub', 'ap-parent');
      mockData([parent, sub], [phase], [subRel]);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      const phaseResult = result.attackPatternsOfPhases[0];
      // Only parent should appear at top level
      expect(phaseResult.attackPatterns).toHaveLength(1);
      expect(phaseResult.attackPatterns[0].attack_pattern_id).toBe('ap-parent');
      // Sub-technique should be listed under parent
      expect(phaseResult.attackPatterns[0].subAttackPatterns).toHaveLength(1);
      expect(phaseResult.attackPatterns[0].subAttackPatterns[0].attack_pattern_id).toBe('ap-sub');
      expect(phaseResult.attackPatterns[0].subAttackPatterns[0].name).toBe('PowerShell');
    });

    it('should build correct subAttackPatternsSearchText', async () => {
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'execution', 2);
      const parent = buildAttackPattern('ap-parent', 'Scripting', ['phase-1'], 'T1059', undefined, ['ap-sub-1', 'ap-sub-2']);
      const sub1 = buildAttackPattern('ap-sub-1', 'PowerShell', ['phase-1'], 'T1059.001', 'Desc PowerShell');
      const sub2 = buildAttackPattern('ap-sub-2', 'Bash', ['phase-1'], 'T1059.004', 'Desc Bash');
      const subRel1 = buildSubTechniqueRelation('ap-sub-1', 'ap-parent');
      const subRel2 = buildSubTechniqueRelation('ap-sub-2', 'ap-parent');
      mockData([parent, sub1, sub2], [phase], [subRel1, subRel2]);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      const parentResult = result.attackPatternsOfPhases[0].attackPatterns[0];
      expect(parentResult.subAttackPatternsSearchText).toContain('T1059.001');
      expect(parentResult.subAttackPatternsSearchText).toContain('PowerShell');
      expect(parentResult.subAttackPatternsSearchText).toContain('Desc PowerShell');
      expect(parentResult.subAttackPatternsSearchText).toContain('T1059.004');
      expect(parentResult.subAttackPatternsSearchText).toContain('Bash');
    });

    it('should distribute attack patterns across multiple kill chain phases', async () => {
      const phase1 = buildKillChainPhase('phase-1', 'mitre-attack', 'initial-access', 1);
      const phase2 = buildKillChainPhase('phase-2', 'mitre-attack', 'execution', 2);
      const ap1 = buildAttackPattern('ap-1', 'Phishing', ['phase-1'], 'T1566');
      const ap2 = buildAttackPattern('ap-2', 'PowerShell', ['phase-2'], 'T1059.001');
      const ap3 = buildAttackPattern('ap-3', 'Multi-phase', ['phase-1', 'phase-2'], 'T1078');
      mockData([ap1, ap2, ap3], [phase1, phase2], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result.attackPatternsOfPhases).toHaveLength(2);
      const phase1Result = result.attackPatternsOfPhases.find((p) => p.kill_chain_id === 'phase-1');
      const phase2Result = result.attackPatternsOfPhases.find((p) => p.kill_chain_id === 'phase-2');
      expect(phase1Result?.attackPatterns).toHaveLength(2); // ap1 and ap3
      expect(phase2Result?.attackPatterns).toHaveLength(2); // ap2 and ap3
    });

    it('should preserve killChainPhasesIds on each attack pattern', async () => {
      const phase1 = buildKillChainPhase('phase-1', 'mitre-attack', 'initial-access', 1);
      const phase2 = buildKillChainPhase('phase-2', 'mitre-attack', 'execution', 2);
      const ap = buildAttackPattern('ap-1', 'Multi-phase AP', ['phase-1', 'phase-2'], 'T1078');
      mockData([ap], [phase1, phase2], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      const apInPhase1 = result.attackPatternsOfPhases.find((p) => p.kill_chain_id === 'phase-1')?.attackPatterns[0];
      expect(apInPhase1?.killChainPhasesIds).toContain('phase-1');
      expect(apInPhase1?.killChainPhasesIds).toContain('phase-2');
    });
  });

  describe('edge cases', () => {
    it('should exclude kill chain phases that have no attack patterns', async () => {
      const phase1 = buildKillChainPhase('phase-1', 'mitre-attack', 'initial-access', 1);
      const phase2 = buildKillChainPhase('phase-2', 'mitre-attack', 'exfiltration', 9);
      // Only phase-1 has an attack pattern
      const ap = buildAttackPattern('ap-1', 'Phishing', ['phase-1'], 'T1566');
      mockData([ap], [phase1, phase2], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result.attackPatternsOfPhases).toHaveLength(1);
      expect(result.attackPatternsOfPhases[0].kill_chain_id).toBe('phase-1');
    });

    it('should exclude attack patterns not linked to any kill chain phase', async () => {
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'initial-access', 1);
      const apLinked = buildAttackPattern('ap-1', 'Phishing', ['phase-1'], 'T1566');
      // This attack pattern has no kill chain phase entry
      const apUnlinked = buildAttackPattern('ap-2', 'Orphan AP', [], 'T9999');
      mockData([apLinked, apUnlinked], [phase], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result.attackPatternsOfPhases[0].attackPatterns).toHaveLength(1);
      expect(result.attackPatternsOfPhases[0].attackPatterns[0].attack_pattern_id).toBe('ap-1');
    });

    it('should exclude sub-techniques from the top-level list of a kill chain phase', async () => {
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'execution', 2);
      const parent = buildAttackPattern('ap-parent', 'Scripting', ['phase-1'], 'T1059', undefined, ['ap-sub-1', 'ap-sub-2']);
      const sub1 = buildAttackPattern('ap-sub-1', 'PowerShell', ['phase-1'], 'T1059.001');
      const sub2 = buildAttackPattern('ap-sub-2', 'Bash', ['phase-1'], 'T1059.004');
      const subRel1 = buildSubTechniqueRelation('ap-sub-1', 'ap-parent');
      const subRel2 = buildSubTechniqueRelation('ap-sub-2', 'ap-parent');
      mockData([parent, sub1, sub2], [phase], [subRel1, subRel2]);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      const topLevelPatterns = result.attackPatternsOfPhases[0].attackPatterns;
      expect(topLevelPatterns).toHaveLength(1);
      expect(topLevelPatterns[0].attack_pattern_id).toBe('ap-parent');
      expect(topLevelPatterns[0].subAttackPatterns).toHaveLength(2);
    });

    it('should handle an attack pattern with no x_mitre_id', async () => {
      const phase = buildKillChainPhase('phase-1', 'custom-chain', 'recon', 0);
      const ap = buildAttackPattern('ap-1', 'Custom Technique', ['phase-1'], undefined);
      mockData([ap], [phase], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result.attackPatternsOfPhases[0].attackPatterns[0].x_mitre_id).toBeUndefined();
    });

    it('should handle a sub-technique whose parent is not found in the attack patterns list', async () => {
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'execution', 2);
      const parent = buildAttackPattern('ap-parent', 'Scripting', ['phase-1'], 'T1059');
      // Relation references an unknown fromId
      const orphanSubRel = buildSubTechniqueRelation('ap-unknown-sub', 'ap-parent');
      mockData([parent], [phase], [orphanSubRel]);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      // Parent should still appear; sub not found → empty subAttackPatterns
      expect(result.attackPatternsOfPhases[0].attackPatterns).toHaveLength(1);
      expect(result.attackPatternsOfPhases[0].attackPatterns[0].subAttackPatterns).toHaveLength(0);
    });

    it('should handle completely empty data (no attack patterns, no phases, no relations)', async () => {
      mockData([], [], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result).toEqual({ attackPatternsOfPhases: [] });
    });

    it('should not include a phase entry for an attack pattern linked to a kill chain phase that does not exist', async () => {
      // phase-99 doesn't exist in the kill chain phases list
      const ap = buildAttackPattern('ap-1', 'Phishing', ['phase-99'], 'T1566');
      const phase = buildKillChainPhase('phase-1', 'mitre-attack', 'initial-access', 1);
      mockData([ap], [phase], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      // phase-1 has no matching attack patterns, so it should be excluded
      expect(result.attackPatternsOfPhases).toHaveLength(0);
    });

    it('should handle multiple kill chains (e.g. mitre-attack and a custom chain) independently', async () => {
      const mitrePhase = buildKillChainPhase('phase-mitre', 'mitre-attack', 'initial-access', 1);
      const customPhase = buildKillChainPhase('phase-custom', 'custom-chain', 'recon', 1);
      const mitreAp = buildAttackPattern('ap-mitre', 'Phishing', ['phase-mitre'], 'T1566');
      const customAp = buildAttackPattern('ap-custom', 'OSINT Recon', ['phase-custom']);
      mockData([mitreAp, customAp], [mitrePhase, customPhase], []);

      const result = await getAttackPatternsMatrix(testContext, ADMIN_USER);
      expect(result.attackPatternsOfPhases).toHaveLength(2);
      const mitrePhasResult = result.attackPatternsOfPhases.find((p) => p.kill_chain_name === 'mitre-attack');
      const customPhaseResult = result.attackPatternsOfPhases.find((p) => p.kill_chain_name === 'custom-chain');
      expect(mitrePhasResult?.attackPatterns[0].attack_pattern_id).toBe('ap-mitre');
      expect(customPhaseResult?.attackPatterns[0].attack_pattern_id).toBe('ap-custom');
    });
  });
});

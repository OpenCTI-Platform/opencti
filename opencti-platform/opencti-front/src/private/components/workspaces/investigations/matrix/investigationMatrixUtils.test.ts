import { describe, expect, it } from 'vitest';
import {
  formatAttackPatternLabel,
  getInvestigationAttackPatterns,
  getKillChainTechniqueIds,
  getUnplacedAttackPatterns,
  MatrixPhase,
  pickDefaultKillChain,
} from './investigationMatrixUtils';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';

const object = (id: string, entity_type: string, name?: string) => (
  { id, entity_type, name, parent_types: [] } as unknown as ObjectToParse
);

const phase = (kill_chain_name: string, attackPatterns: { id: string; subs?: string[] }[]) => ({
  kill_chain_id: `${kill_chain_name}-phase`,
  kill_chain_name,
  phase_name: 'execution',
  x_opencti_order: 1,
  attackPatterns: attackPatterns.map(({ id, subs = [] }) => ({
    attack_pattern_id: id,
    name: id,
    description: null,
    x_mitre_id: null,
    subAttackPatterns: subs.map((sub) => ({ attack_pattern_id: sub, name: sub, description: null, x_mitre_id: null })),
    subAttackPatternsSearchText: null,
    killChainPhasesIds: [],
  })),
}) as unknown as MatrixPhase;

describe('getInvestigationAttackPatterns', () => {
  it('keeps only attack patterns, with their main representative as name', () => {
    const result = getInvestigationAttackPatterns([
      object('ap-1', 'Attack-Pattern', 'Alpha'),
      object('is-1', 'Intrusion-Set', 'APT'),
      object('rel-1', 'uses'),
    ]);
    expect(result).toEqual([{ id: 'ap-1', name: 'Alpha' }]);
  });

  it('keeps the T-code of an attack pattern', () => {
    const result = getInvestigationAttackPatterns([
      { ...object('ap-2', 'Attack-Pattern', 'Phishing'), x_mitre_id: 'T1566' } as ObjectToParse,
    ]);
    expect(result).toEqual([{ id: 'ap-2', name: 'Phishing', x_mitre_id: 'T1566' }]);
  });
});

describe('formatAttackPatternLabel', () => {
  it('labels an attack pattern with its T-code and name', () => {
    expect(formatAttackPatternLabel({ id: 'a', name: 'Phishing', x_mitre_id: 'T1566' })).toBe('T1566 - Phishing');
  });

  it('labels an attack pattern without T-code by its name', () => {
    expect(formatAttackPatternLabel({ id: 'a', name: 'Custom' })).toBe('Custom');
  });
});

describe('pickDefaultKillChain', () => {
  it('prefers mitre-attack when present', () => {
    expect(pickDefaultKillChain(['b', 'mitre-attack'])).toBe('mitre-attack');
  });

  it('falls back to the first kill chain alphabetically', () => {
    expect(pickDefaultKillChain(['zeta', 'alpha'])).toBe('alpha');
  });

  it('gives undefined without kill chain', () => {
    expect(pickDefaultKillChain([])).toBeUndefined();
  });
});

describe('getKillChainTechniqueIds', () => {
  it('collects techniques and sub-techniques of the selected kill chain only', () => {
    const phases = [
      phase('mitre-attack', [{ id: 'ap-1', subs: ['ap-1.1'] }, { id: 'ap-2' }]),
      phase('other', [{ id: 'ap-3' }]),
    ];
    expect(getKillChainTechniqueIds(phases, 'mitre-attack')).toEqual(new Set(['ap-1', 'ap-1.1', 'ap-2']));
  });
});

describe('getUnplacedAttackPatterns', () => {
  it('returns the attack patterns absent from the kill chain (revoked or unknown) only', () => {
    const placed = { id: 'ap-1', name: 'Placed' };
    const revoked = { id: 'ap-revoked', name: 'Revoked' };
    expect(getUnplacedAttackPatterns([placed, revoked], new Set(['ap-1']))).toEqual([revoked]);
  });
});

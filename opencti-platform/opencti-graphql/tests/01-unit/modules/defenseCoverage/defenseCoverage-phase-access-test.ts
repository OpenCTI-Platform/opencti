import { describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/defenseCoverage/defenseGap/defenseGap';
import { buildDefenseMatrix, findDefenseGaps } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import type { DefenseSnapshot } from '../../../../src/modules/defenseCoverage/defenseCoverage-reader';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const technique = { id: 'attack-pattern-1', name: 'Phishing', x_mitre_id: 'T1566', kill_chain_phase_ids: ['phase-open', 'phase-restricted'] };
const snapshot: DefenseSnapshot = {
  version: 'coverage-version',
  techniques: [technique],
  techniquesById: new Map([[technique.id, technique]]),
  phases: [
    { id: 'phase-open', kill_chain_name: 'mitre-attack', phase_name: 'initial-access', x_opencti_order: 1 },
    { id: 'phase-restricted', kill_chain_name: 'restricted-chain', phase_name: 'restricted-phase', x_opencti_order: 2 },
  ],
  evidenceIds: [technique.id, 'phase-open', 'phase-restricted'],
};

vi.mock('../../../../src/modules/defenseCoverage/defenseCoverage-reader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/defenseCoverage/defenseCoverage-reader')>()),
  getDefenseSnapshot: vi.fn(async () => snapshot),
  getAccessPredicate: vi.fn(async () => (id: string) => !!id && id !== 'phase-restricted'),
  getThreatOverlay: vi.fn(async () => ({ threats_count: 0, usages: new Map() })),
}));

vi.mock('../../../../src/modules/defenseCoverage/defenseCoverage-compute', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/defenseCoverage/defenseCoverage-compute')>()),
  loadDefensePlatforms: vi.fn(async () => []),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async () => []),
}));

const context = {} as AuthContext;
const user = {} as AuthUser;

describe('Defense coverage kill chain phases per reader', () => {
  it('should leave the phases the reader cannot access out of the tactics and the cells of the matrix', async () => {
    const matrix = await buildDefenseMatrix(context, user, {});
    expect(matrix.tactics.map((tactic) => tactic.kill_chain_phase_id)).toEqual(['phase-open']);
    expect(matrix.cells.map((cell) => cell.kill_chain_phase_ids)).toEqual([['phase-open']]);
  });

  it('should leave the phases the reader cannot access out of the gaps', async () => {
    const gaps = await findDefenseGaps(context, user, {});
    expect(gaps.edges.length).toBeGreaterThan(0);
    gaps.edges.forEach(({ node }) => expect(node.kill_chain_phase_ids).toEqual(['phase-open']));
  });
});

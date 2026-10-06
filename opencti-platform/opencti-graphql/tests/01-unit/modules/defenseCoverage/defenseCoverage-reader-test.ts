import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fullEntitiesList, fullRelationsList, internalFindByIds } from '../../../../src/database/middleware-loader';
import { elCount } from '../../../../src/database/engine';
import { clearDefenseSnapshotCache, getAccessPredicate, getDefenseSnapshot, getThreatOverlay } from '../../../../src/modules/defenseCoverage/defenseCoverage-reader';
import { getDefenseThreatsVersion } from '../../../../src/modules/defenseCoverage/defenseCoverage-state';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(async () => []),
  fullRelationsList: vi.fn(async () => []),
  internalFindByIds: vi.fn(async () => []),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elCount: vi.fn(async () => 1),
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(async () => ({})),
}));

vi.mock('../../../../src/modules/defenseCoverage/defenseCoverage-state', () => ({
  getDefenseCoverageVersion: vi.fn(async () => 'coverage-version'),
  getDefenseOverlayVersion: vi.fn(async () => 'overlay-version'),
  getDefenseThreatsVersion: vi.fn(async () => 'threats-version'),
}));

const DRAFT_ID = 'draft-workspace-1';
const reader = {
  id: 'reader',
  draft_context: DRAFT_ID,
  groups: [],
  roles: [],
  organizations: [],
  capabilities: [],
  allowed_marking: [],
} as unknown as AuthUser;
const draftContext = { draft_context: DRAFT_ID, user: reader } as unknown as AuthContext;

const expectPublished = (calls: unknown[][]) => {
  expect(calls.length).toBeGreaterThan(0);
  calls.forEach(([context, user]) => {
    expect((context as AuthContext).draft_context).toBeUndefined();
    expect((context as AuthContext).user?.draft_context).toBeUndefined();
    expect((user as AuthUser).draft_context).toBeUndefined();
  });
};

describe('Defense coverage reader caches', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearDefenseSnapshotCache();
  });

  it('should load the shared snapshot from published knowledge for a reader in a draft', async () => {
    await getDefenseSnapshot(draftContext);
    expectPublished([...vi.mocked(fullEntitiesList).mock.calls, ...vi.mocked(fullRelationsList).mock.calls]);
  });

  it('should evaluate the shared access cache on published knowledge for a reader in a draft', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ internal_id: 'attack-pattern-1', name: 'Phishing' }] as never);
    const snapshot = await getDefenseSnapshot(draftContext);
    await getAccessPredicate(draftContext, reader, snapshot);
    expectPublished(vi.mocked(internalFindByIds).mock.calls);
  });

  it('should compute the shared threat overlay on published knowledge for a reader in a draft', async () => {
    await getThreatOverlay(draftContext, reader, { mode: 'ALL' });
    expectPublished(vi.mocked(fullRelationsList).mock.calls);
    expectPublished(vi.mocked(elCount).mock.calls);
  });

  it('should count every threat the reader can access in the ALL scope, those without a used technique included', async () => {
    vi.mocked(elCount).mockResolvedValueOnce(3);
    vi.mocked(fullRelationsList).mockResolvedValueOnce([
      { internal_id: 'uses-1', fromId: 'intrusion-set-1', toId: 'attack-pattern-1', confidence: 80 },
    ] as never);
    const overlay = await getThreatOverlay(draftContext, reader, { mode: 'ALL' });
    expect(overlay.threats_count).toEqual(3);
    expect(overlay.usages.get('attack-pattern-1')).toEqual([{ threat_id: 'intrusion-set-1', relationship_id: 'uses-1', confidence: 80 }]);
  });

  it('should not load any usage when the reader can access no threat in the ALL scope', async () => {
    vi.mocked(elCount).mockResolvedValueOnce(0);
    const overlay = await getThreatOverlay(draftContext, reader, { mode: 'ALL' });
    expect(overlay.threats_count).toEqual(0);
    expect(vi.mocked(fullRelationsList)).not.toHaveBeenCalled();
  });

  it('should recompute a filtered threat overlay when the threats change and keep the overlay of selected threats', async () => {
    const filtered = { mode: 'FILTERED', filters: { mode: 'and', filters: [{ key: ['name'], values: ['APT'] }], filterGroups: [] } } as never;
    const selected = { mode: 'SELECTED', threatIds: ['intrusion-set-1'] } as never;
    vi.mocked(getDefenseThreatsVersion).mockResolvedValue('threats-1');
    await getThreatOverlay(draftContext, reader, filtered);
    await getThreatOverlay(draftContext, reader, selected);
    await getThreatOverlay(draftContext, reader, filtered);
    expect(vi.mocked(fullEntitiesList)).toHaveBeenCalledTimes(1);
    vi.mocked(getDefenseThreatsVersion).mockResolvedValue('threats-2');
    await getThreatOverlay(draftContext, reader, filtered);
    await getThreatOverlay(draftContext, reader, selected);
    expect(vi.mocked(fullEntitiesList)).toHaveBeenCalledTimes(2);
    expect(vi.mocked(internalFindByIds)).toHaveBeenCalledTimes(1);
  });
});

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

  it('should not fold a sub-technique into its parent through a revoked relationship', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ internal_id: 'sub-1' }, { internal_id: 'sub-2' }, { internal_id: 'parent' }] as never);
    vi.mocked(fullRelationsList).mockResolvedValueOnce([
      { internal_id: 'rel-1', fromId: 'sub-1', toId: 'parent' },
      { internal_id: 'rel-2', fromId: 'sub-2', toId: 'parent', revoked: true },
    ] as never);
    const snapshot = await getDefenseSnapshot(draftContext);
    expect(snapshot.techniquesById.get('sub-1')?.parent_id).toEqual('parent');
    expect(snapshot.techniquesById.get('sub-2')?.parent_id).toBeUndefined();
  });

  it('should leave the revoked threats and usages out of the ALL scope', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ internal_id: 'intrusion-set-revoked' }] as never);
    vi.mocked(elCount).mockResolvedValueOnce(3);
    vi.mocked(fullRelationsList).mockResolvedValueOnce([
      { internal_id: 'uses-1', fromId: 'intrusion-set-1', toId: 'attack-pattern-1', confidence: 80 },
      { internal_id: 'uses-2', fromId: 'intrusion-set-revoked', toId: 'attack-pattern-1', confidence: 80 },
      { internal_id: 'uses-3', fromId: 'intrusion-set-1', toId: 'attack-pattern-2', confidence: 80, revoked: true },
    ] as never);
    const overlay = await getThreatOverlay(draftContext, reader, { mode: 'ALL' });
    expect(overlay.threats_count).toEqual(2);
    expect(overlay.usages.get('attack-pattern-1')).toEqual([{ threat_id: 'intrusion-set-1', relationship_id: 'uses-1', confidence: 80 }]);
    expect(overlay.usages.has('attack-pattern-2')).toEqual(false);
  });

  it('should leave a revoked threat out of the selected scope', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce([{ internal_id: 'intrusion-set-1' }, { internal_id: 'intrusion-set-revoked', revoked: true }] as never);
    const overlay = await getThreatOverlay(draftContext, reader, { mode: 'SELECTED', threatIds: ['intrusion-set-1', 'intrusion-set-revoked'] } as never);
    expect(overlay.threats_count).toEqual(1);
    expect(vi.mocked(fullRelationsList).mock.calls[0][3]).toEqual(expect.objectContaining({ fromId: ['intrusion-set-1'] }));
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

  it.each([
    ['the service account flag', { user: { user_service_account: true } }],
    ['the linked individual', { user: { individual_id: 'individual-1' } }],
    ['the membership of the platform organization', { context: { user_inside_platform_organization: true } }],
  ])('should evaluate the access of a reader again when %s changes', async (_, change: { user?: object; context?: object }) => {
    vi.mocked(fullEntitiesList).mockResolvedValueOnce([{ internal_id: 'attack-pattern-1', name: 'Phishing' }] as never);
    const snapshot = await getDefenseSnapshot(draftContext);
    await getAccessPredicate(draftContext, reader, snapshot);
    await getAccessPredicate(draftContext, reader, snapshot);
    expect(vi.mocked(internalFindByIds)).toHaveBeenCalledTimes(1);
    const changedReader = { ...reader, ...change.user } as AuthUser;
    await getAccessPredicate({ ...draftContext, ...change.context } as AuthContext, changedReader, snapshot);
    expect(vi.mocked(internalFindByIds)).toHaveBeenCalledTimes(2);
  });
});

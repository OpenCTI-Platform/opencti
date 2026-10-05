import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { addGraphClusterToInvestigation, PROMOTION_MAX_MEMBERS, promoteGraphCluster } from '../../../../src/modules/graphAnalytics/graphAnalytics-domain';
import { addClusterPromotion, loadGraphClusters } from '../../../../src/modules/graphAnalytics/graphAnalytics-store';
import { elCount, elFindByIds, elList } from '../../../../src/database/engine';
import { addGrouping } from '../../../../src/modules/grouping/grouping-domain';
import { addCampaign } from '../../../../src/domain/campaign';
import { addWorkspace, workspaceEditField } from '../../../../src/modules/workspace/workspace-domain';
import { GraphClusterPromotionTarget } from '../../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../../src/utils/access';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elCount: vi.fn(),
  elList: vi.fn(),
  elFindByIds: vi.fn(),
}));
vi.mock('../../../../src/modules/graphAnalytics/graphAnalytics-store', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/graphAnalytics/graphAnalytics-store')>()),
  loadGraphClusters: vi.fn(),
  addClusterPromotion: vi.fn(),
}));
vi.mock('../../../../src/modules/grouping/grouping-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/grouping/grouping-domain')>()),
  addGrouping: vi.fn(),
}));
vi.mock('../../../../src/domain/campaign', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/domain/campaign')>()),
  addCampaign: vi.fn(),
}));
vi.mock('../../../../src/modules/workspace/workspace-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/workspace/workspace-domain')>()),
  addWorkspace: vi.fn(),
  workspaceEditField: vi.fn(),
}));

const context = { source: 'test', otp_mandatory: false } as unknown as AuthContext;
const members = (count: number) => Array.from({ length: count }, (_, i) => ({ internal_id: `member-${i}`, entity_type: 'Malware' }));

describe('graph analytics promotion of a cluster that grows while it is promoted', () => {
  beforeEach(() => {
    vi.mocked(loadGraphClusters).mockReset().mockResolvedValue([{ internal_id: 'cluster-1', name: 'Cluster 1', cluster_features: [] }] as never);
    // the count read first still fits the limit
    vi.mocked(elCount).mockReset().mockResolvedValue(PROMOTION_MAX_MEMBERS as never);
    vi.mocked(elList).mockReset();
    vi.mocked(elFindByIds).mockReset().mockResolvedValue({} as never);
    vi.mocked(addClusterPromotion).mockReset();
    vi.mocked(addGrouping).mockReset().mockResolvedValue({ internal_id: 'grouping-1', entity_type: 'Grouping' } as never);
    vi.mocked(addCampaign).mockReset();
    vi.mocked(addWorkspace).mockReset();
    vi.mocked(workspaceEditField).mockReset();
  });

  it('should refuse the promotion when the member query returns more members than the limit', async () => {
    vi.mocked(elList).mockResolvedValue(members(PROMOTION_MAX_MEMBERS + 1) as never);
    const promotion = promoteGraphCluster(context, SYSTEM_USER, 'cluster-1', { target: GraphClusterPromotionTarget.Grouping, name: 'Promoted' });
    await expect(promotion).rejects.toThrow('Graph cluster has too many accessible members to be promoted');
    expect(vi.mocked(elList).mock.calls[0][3]).toMatchObject({ maxSize: PROMOTION_MAX_MEMBERS + 1 });
    expect(addGrouping).not.toHaveBeenCalled();
    expect(addCampaign).not.toHaveBeenCalled();
    expect(addClusterPromotion).not.toHaveBeenCalled();
  });

  it('should promote every member of a cluster at the limit', async () => {
    vi.mocked(elList).mockResolvedValue(members(PROMOTION_MAX_MEMBERS) as never);
    await promoteGraphCluster(context, SYSTEM_USER, 'cluster-1', { target: GraphClusterPromotionTarget.Grouping, name: 'Promoted' });
    expect(addGrouping).toHaveBeenCalledTimes(1);
    expect(vi.mocked(addGrouping).mock.calls[0][2].objects).toHaveLength(PROMOTION_MAX_MEMBERS);
    expect(addClusterPromotion).toHaveBeenCalledWith(context, expect.objectContaining({ internal_id: 'cluster-1' }), 'grouping-1');
  });

  it('should refuse the investigation when the member query returns more members than the limit', async () => {
    vi.mocked(elList).mockResolvedValue(members(PROMOTION_MAX_MEMBERS + 1) as never);
    const investigation = addGraphClusterToInvestigation(context, SYSTEM_USER, 'cluster-1');
    await expect(investigation).rejects.toThrow('Graph cluster has too many accessible elements to be added to an investigation');
    expect(vi.mocked(elList).mock.calls[0][3]).toMatchObject({ maxSize: PROMOTION_MAX_MEMBERS + 1 });
    expect(addWorkspace).not.toHaveBeenCalled();
    expect(workspaceEditField).not.toHaveBeenCalled();
  });
});

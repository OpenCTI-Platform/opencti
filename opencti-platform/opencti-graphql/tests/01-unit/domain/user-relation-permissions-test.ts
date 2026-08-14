import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn(),
  deleteElementById: vi.fn(),
  deleteRelationsByFromAndTo: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
  updatedInputsToData: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  fullEntitiesThoughAggregationConnection: vi.fn(),
  fullEntitiesThroughRelationsToList: vi.fn(),
  fullRelationsList: vi.fn(),
  internalFindByIds: vi.fn(),
  internalLoadById: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  pageRegardingEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/database/redis', () => ({
  delEditContext: vi.fn(),
  notify: vi.fn().mockResolvedValue({}),
  setEditContext: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/utils/access', async () => {
  const actual: any = await vi.importActual('../../../src/utils/access');
  return {
    ...actual,
    isOnlyOrgaAdmin: vi.fn().mockReturnValue(true),
    isUserHasCapability: vi.fn().mockReturnValue(true),
  };
});

import { userAddRelation, userIdDeleteRelation } from '../../../src/domain/user';
import { createRelation, deleteRelationsByFromAndTo } from '../../../src/database/middleware';
import { internalLoadById } from '../../../src/database/middleware-loader';
import { RELATION_PARTICIPATE_TO } from '../../../src/schema/internalRelationship';

describe('user relation permissions', () => {
  const context = {} as any;
  const orgAdmin = {
    id: 'org-admin-id',
    user_email: 'org-admin@opencti.io',
    administrated_organizations: [{ id: 'org-1', grantable_groups: [] }],
  } as any;

  beforeEach(() => {
    vi.clearAllMocks();
    (internalLoadById as any).mockResolvedValue({
      id: 'target-user-id',
      user_email: 'target@opencti.io',
      [RELATION_PARTICIPATE_TO]: ['org-1'],
    });
    (createRelation as any).mockResolvedValue({
      toType: 'organization',
      to: { entity_type: 'Organization', name: 'Org 1' },
    });
    (deleteRelationsByFromAndTo as any).mockResolvedValue({
      to: { entity_type: 'Organization', name: 'Org 1' },
    });
  });

  it('forbids adding participate-to relation outside administrated organizations', async () => {
    await expect(userAddRelation(context, orgAdmin, 'target-user-id', {
      relationship_type: RELATION_PARTICIPATE_TO,
      toId: 'org-2',
    })).rejects.toBeDefined();

    expect(createRelation).not.toHaveBeenCalled();
  });

  it('allows deleting participate-to relation through dedicated path when organization is administrated', async () => {
    await userIdDeleteRelation(context, orgAdmin, 'target-user-id', 'org-1', RELATION_PARTICIPATE_TO);

    expect(deleteRelationsByFromAndTo).toHaveBeenCalledWith(
      context,
      orgAdmin,
      'target-user-id',
      'org-1',
      RELATION_PARTICIPATE_TO,
      expect.any(String),
    );
  });
});

import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middleware from '../../../src/database/middleware';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import * as redis from '../../../src/database/redis';
import * as access from '../../../src/utils/access';
import * as userActionListener from '../../../src/listener/UserActionListener';
import * as containerDomain from '../../../src/domain/container';
import { duplicateWorkspace } from '../../../src/modules/workspace/workspace-domain';

const context = {} as any;
const user = { id: 'user-id' } as any;

const duplicateInput = {
  id: 'source-id',
  name: 'Duplicated workspace',
};

describe('workspace duplication', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(access, 'isUserHasCapability').mockReturnValue(true);
    vi.spyOn(middleware, 'createEntity').mockResolvedValue({
      id: 'duplicated-id',
      type: 'dashboard',
      name: duplicateInput.name,
    } as any);
    vi.spyOn(containerDomain, 'filterUnwantedEntitiesOut').mockResolvedValue([]);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue(undefined as any);
    vi.spyOn(redis, 'notify').mockResolvedValue({ id: 'duplicated-id' } as any);
  });

  it('duplicates a dashboard source without filtering investigation entities', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: 'dashboard',
      manifest: 'source-manifest',
      tags: ['source-tag'],
      description: 'source-description',
    } as any);

    await duplicateWorkspace(context, user, duplicateInput);

    expect(middlewareLoader.storeLoadById).toHaveBeenCalledExactlyOnceWith(context, user, duplicateInput.id, 'Workspace');

    expect(containerDomain.filterUnwantedEntitiesOut).not.toHaveBeenCalled();
    expect(middleware.createEntity).toHaveBeenCalledWith(
      context,
      user,
      expect.objectContaining({
        type: 'dashboard',
        manifest: 'source-manifest',
        tags: ['source-tag'],
        description: 'source-description',
        name: 'Duplicated workspace',
        restricted_members: [{ id: 'user-id', access_right: 'admin' }],
      }),
      'Workspace',
    );
  });

  it('filters investigation entities before creating a duplicate', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: 'investigation',
      manifest: 'investigation-manifest',
      tags: ['source-tag'],
      description: 'source-description',
      investigated_entities_ids: ['visible-id', 'hidden-id'],
      graph_data: 'source-layout',
    } as any);
    const filterSpy = vi.mocked(containerDomain.filterUnwantedEntitiesOut);
    filterSpy.mockResolvedValue(['visible-id']);

    await duplicateWorkspace(context, user, duplicateInput);

    expect(middlewareLoader.storeLoadById).toHaveBeenCalledExactlyOnceWith(context, user, duplicateInput.id, 'Workspace');

    expect(containerDomain.filterUnwantedEntitiesOut).toHaveBeenCalledWith({
      context,
      user,
      ids: ['visible-id', 'hidden-id'],
    });
    expect(middleware.createEntity).toHaveBeenCalledWith(
      context,
      user,
      {
        type: 'investigation',
        manifest: 'investigation-manifest',
        tags: ['source-tag'],
        description: 'source-description',
        investigated_entities_ids: ['visible-id'],
        name: duplicateInput.name,
        restricted_members: [{ id: 'user-id', access_right: 'admin' }],
      },
      'Workspace',
    );
  });

  it('uses an empty investigation entity list when the source has none', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: 'investigation',
    } as any);
    const filterSpy = vi.mocked(containerDomain.filterUnwantedEntitiesOut);
    filterSpy.mockResolvedValue([]);

    await duplicateWorkspace(context, user, duplicateInput);

    expect(filterSpy).toHaveBeenCalledWith({ context, user, ids: [] });
    expect(middleware.createEntity).toHaveBeenCalledWith(
      context,
      user,
      expect.objectContaining({ investigated_entities_ids: [] }),
      'Workspace',
    );
  });

  it('rejects a missing source before checking capabilities or creating', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue(undefined as any);

    await expect(duplicateWorkspace(context, user, duplicateInput)).rejects.toThrow();
    expect(access.isUserHasCapability).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });

  it.each([
    ['investigation', 'EXPLORE_EXUPDATE'],
    ['dashboard', 'INVESTIGATION_INUPDATE'],
  ] as const)('rejects a %s source with only %s', async (sourceType, capability) => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: sourceType,
    } as any);
    vi.mocked(access.isUserHasCapability).mockImplementation((_, requiredCapability) => requiredCapability === capability);

    await expect(duplicateWorkspace(context, user, duplicateInput)).rejects.toThrow();

    expect(containerDomain.filterUnwantedEntitiesOut).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });

  it('rejects an unsupported type before creating', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: 'unsupported',
    } as any);

    await expect(duplicateWorkspace(context, user, duplicateInput)).rejects.toThrow();

    expect(access.isUserHasCapability).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });

  it.each([
    ['dashboard', 'EXPLORE_EXUPDATE'],
    ['investigation', 'INVESTIGATION_INUPDATE'],
  ] as const)('rejects %s duplication when its capability is missing', async (sourceType, capability) => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: sourceType,
    } as any);
    vi.spyOn(access, 'isUserHasCapability').mockReturnValue(false);

    await expect(duplicateWorkspace(context, user, duplicateInput)).rejects.toThrow();

    expect(access.isUserHasCapability).toHaveBeenCalledWith(user, capability);
    expect(containerDomain.filterUnwantedEntitiesOut).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });
});

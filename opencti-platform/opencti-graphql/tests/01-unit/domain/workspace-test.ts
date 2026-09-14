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
  type: 'dashboard',
  name: 'Duplicated workspace',
  manifest: 'input-manifest',
  tags: ['input-tag'],
  description: 'input-description',
};

describe('duplicateWorkspace', () => {
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

    await duplicateWorkspace(context, user, duplicateInput as any);

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
    } as any);
    const filterSpy = vi.mocked(containerDomain.filterUnwantedEntitiesOut);
    filterSpy.mockResolvedValue(['visible-id']);

    await duplicateWorkspace(context, user, { ...duplicateInput, type: 'investigation' } as any);

    expect(containerDomain.filterUnwantedEntitiesOut).toHaveBeenCalledWith({
      context,
      user,
      ids: ['visible-id', 'hidden-id'],
    });
    expect(middleware.createEntity).toHaveBeenCalledWith(
      context,
      user,
      expect.objectContaining({
        type: 'investigation',
        investigated_entities_ids: ['visible-id'],
      }),
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

    await duplicateWorkspace(context, user, { ...duplicateInput, type: 'investigation' } as any);

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

    await expect(duplicateWorkspace(context, user, duplicateInput as any)).rejects.toThrow();
    expect(access.isUserHasCapability).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });

  it('duplicates a standalone workspace using input fields', async () => {
    await duplicateWorkspace(context, user, {
      type: 'dashboard',
      name: 'Standalone dashboard',
      manifest: 'standalone-manifest',
      tags: ['standalone-tag'],
      description: 'standalone-description',
    } as any);

    expect(middlewareLoader.storeLoadById).not.toHaveBeenCalled();
    expect(middleware.createEntity).toHaveBeenCalledWith(
      context,
      user,
      expect.objectContaining({
        type: 'dashboard',
        name: 'Standalone dashboard',
        manifest: 'standalone-manifest',
      }),
      'Workspace',
    );
  });

  it('rejects an unsupported type before creating', async () => {
    await expect(duplicateWorkspace(context, user, {
      type: 'unsupported',
      name: 'Unsupported workspace',
    } as any)).rejects.toThrow();

    expect(access.isUserHasCapability).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });

  it('rejects when the required type capability is missing', async () => {
    vi.spyOn(access, 'isUserHasCapability').mockReturnValue(false);

    await expect(duplicateWorkspace(context, user, {
      type: 'investigation',
      name: 'Unauthorized investigation',
    } as any)).rejects.toThrow();

    expect(middleware.createEntity).not.toHaveBeenCalled();
  });
});

import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middleware from '../../../src/database/middleware';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import * as redis from '../../../src/database/redis';
import * as access from '../../../src/utils/access';
import * as userActionListener from '../../../src/listener/UserActionListener';
import * as engine from '../../../src/database/engine';
import { duplicateInvestigation, duplicateWorkspace } from '../../../src/modules/workspace/workspace-domain';

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
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue([]);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue(undefined as any);
    vi.spyOn(redis, 'notify').mockResolvedValue({ id: 'duplicated-id' } as any);
  });

  it('preserves dashboard duplication from metadata without requiring a source ID', async () => {
    const loadSpy = vi.spyOn(middlewareLoader, 'storeLoadById');
    const input = {
      type: 'dashboard',
      name: duplicateInput.name,
      manifest: 'source-manifest',
      tags: ['source-tag'],
      description: 'source-description',
    };

    await duplicateWorkspace(context, user, input);

    expect(loadSpy).not.toHaveBeenCalled();
    expect(access.isUserHasCapability).not.toHaveBeenCalled();

    expect(engine.elFindByIds).not.toHaveBeenCalled();
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

  it('excludes Notes and Tasks even when accessible and retains other accessible investigation entities', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: 'investigation',
      manifest: 'investigation-manifest',
      tags: ['source-tag'],
      description: 'source-description',
      investigated_entities_ids: ['note-id', 'task-id', 'malware-id', 'hidden-id'],
      graph_data: 'source-layout',
    } as any);
    vi.mocked(engine.elFindByIds).mockResolvedValue([
      { id: 'note-id', entity_type: 'Note' },
      { id: 'task-id', entity_type: 'Task' },
      { id: 'malware-id', entity_type: 'Malware' },
    ] as any);

    await duplicateInvestigation(context, user, duplicateInput);

    expect(middlewareLoader.storeLoadById).toHaveBeenCalledExactlyOnceWith(context, user, duplicateInput.id, 'Workspace');

    expect(engine.elFindByIds).toHaveBeenCalledWith(
      context,
      user,
      ['note-id', 'task-id', 'malware-id', 'hidden-id'],
    );
    expect(middleware.createEntity).toHaveBeenCalledWith(
      context,
      user,
      {
        type: 'investigation',
        manifest: 'investigation-manifest',
        tags: ['source-tag'],
        description: 'source-description',
        investigated_entities_ids: ['malware-id'],
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

    await duplicateInvestigation(context, user, duplicateInput);

    expect(engine.elFindByIds).toHaveBeenCalledWith(context, user, []);
    expect(middleware.createEntity).toHaveBeenCalledWith(
      context,
      user,
      expect.objectContaining({ investigated_entities_ids: [] }),
      'Workspace',
    );
  });

  it('rejects a missing source before checking capabilities or creating', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue(undefined as any);

    await expect(duplicateInvestigation(context, user, duplicateInput)).rejects.toThrow();
    expect(access.isUserHasCapability).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });

  it('rejects investigation duplication with only the dashboard capability', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: 'investigation',
    } as any);
    vi.mocked(access.isUserHasCapability).mockImplementation((_, requiredCapability) => requiredCapability === 'EXPLORE_EXUPDATE');

    await expect(duplicateInvestigation(context, user, duplicateInput)).rejects.toThrow();

    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });

  it.each(['dashboard', 'unsupported'])('rejects a %s source for investigation duplication', async (type) => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type,
    } as any);

    await expect(duplicateInvestigation(context, user, duplicateInput)).rejects.toThrow();

    expect(access.isUserHasCapability).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });

  it('rejects investigation duplication when its capability is missing', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: 'source-id',
      type: 'investigation',
    } as any);
    vi.spyOn(access, 'isUserHasCapability').mockReturnValue(false);

    await expect(duplicateInvestigation(context, user, duplicateInput)).rejects.toThrow();

    expect(access.isUserHasCapability).toHaveBeenCalledWith(user, 'INVESTIGATION_INUPDATE');
    expect(engine.elFindByIds).not.toHaveBeenCalled();
    expect(middleware.createEntity).not.toHaveBeenCalled();
  });
});

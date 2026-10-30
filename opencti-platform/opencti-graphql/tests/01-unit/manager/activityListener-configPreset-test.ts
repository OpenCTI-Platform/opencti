import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/cache', () => ({ getEntityFromCache: vi.fn() }));
vi.mock('../../../src/database/stream/stream-handler', () => ({ storeActivityEvent: vi.fn() }));

import activityListener from '../../../src/manager/activityListener';
import { publishUserAction, type UserAction } from '../../../src/listener/UserActionListener';
import { getEntityFromCache } from '../../../src/database/cache';
import { storeActivityEvent } from '../../../src/database/stream/stream-handler';
import type { AuthUser } from '../../../src/types/user';

const user = { id: 'user-id', origin: { socket: 'query', user_id: 'user-id' } } as unknown as AuthUser;

describe('Activity listener: config preset import', () => {
  beforeEach(async () => {
    vi.resetAllMocks();
    vi.mocked(getEntityFromCache).mockResolvedValue({ valid_enterprise_edition: true, activity_listeners_users: [] } as never);
    await activityListener.start();
  });

  afterEach(async () => {
    await activityListener.shutdown();
  });

  const importAction = (contextData: unknown) => ({
    user,
    event_type: 'command',
    event_scope: 'import',
    event_access: 'administration',
    status: 'success',
    context_data: contextData,
  }) as unknown as UserAction;

  it('logs the counts of a configuration preset import, which has no mime type', async () => {
    await publishUserAction(importAction({
      file_id: 'config_preset/history/id/import-report.json',
      path: 'config_preset/history/id',
      file_name: 'import-report.json',
      input: { counts: { created: 1, overwritten: 2, skipped: 3, failed: 4 } },
    }));
    expect(storeActivityEvent).toHaveBeenCalledTimes(1);
    expect(storeActivityEvent).toHaveBeenCalledWith(expect.objectContaining({
      type: 'command',
      event_scope: 'import',
      message: 'imports a configuration preset (created: 1, overwritten: 2, skipped: 3, failed: 4), report `import-report.json`',
    }));
  });

  it('keeps the message of the import of a file in an entity', async () => {
    await publishUserAction(importAction({ file_name: 'report.pdf', file_mime: 'application/pdf', entity_name: 'My report' }));
    expect(storeActivityEvent).toHaveBeenCalledWith(expect.objectContaining({
      message: 'asks for `application/pdf` import of `report.pdf` in `My report`',
    }));
  });

  it('logs nothing when the enterprise edition is not active', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ valid_enterprise_edition: false } as never);
    await publishUserAction(importAction({ file_name: 'report.pdf', file_mime: 'application/pdf', entity_name: 'My report' }));
    expect(storeActivityEvent).not.toHaveBeenCalled();
  });
});

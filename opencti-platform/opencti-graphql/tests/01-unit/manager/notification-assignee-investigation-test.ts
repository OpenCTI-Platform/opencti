import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthUser } from '../../../src/types/user';

const getEntitiesListFromCache = vi.fn();
const getEntityFromCache = vi.fn();

vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: (...args: any[]) => getEntitiesListFromCache(...args),
  getEntityFromCache: (...args: any[]) => getEntityFromCache(...args),
}));

import { getNotifications } from '../../../src/manager/notificationManager';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { ACCOUNT_STATUS_ACTIVE } from '../../../src/config/conf';

const analyst = {
  id: 'analyst',
  internal_id: 'analyst',
  account_status: ACCOUNT_STATUS_ACTIVE,
  groups: [],
  organizations: [],
  personal_notifiers: [],
} as unknown as AuthUser;

describe('Built-in assignee and participant trigger', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getEntityFromCache.mockResolvedValue({ platform_notifier_auto_trigger_assignee: true });
    getEntitiesListFromCache.mockImplementation((_context: unknown, _user: unknown, type: string) => Promise.resolve(type === ENTITY_TYPE_USER ? [analyst] : []));
  });

  it('delivers the Case Autopilot events of a case to its assignees and participants', async () => {
    const triggers = await getNotifications({} as any);
    const assignee = triggers.find(({ trigger }) => trigger.internal_id === `default-trigger-${analyst.id}`);
    expect(assignee?.trigger.event_types).toEqual([
      'create', 'update', 'delete',
      'investigation_awaiting_approval', 'investigation_completed', 'investigation_failed',
    ]);
  });

  it('keeps the platform trigger on knowledge changes only', async () => {
    const triggers = await getNotifications({} as any);
    const platform = triggers.find(({ trigger }) => trigger.internal_id === `platform-notification-${analyst.id}`);
    expect(platform?.trigger.event_types ?? []).not.toContain('investigation_completed');
  });
});

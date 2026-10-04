import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthUser } from '../../../../src/types/user';

const getEntitiesListFromCache = vi.fn();
const getEntityFromCache = vi.fn();

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: (...args: any[]) => getEntitiesListFromCache(...args),
  getEntityFromCache: (...args: any[]) => getEntityFromCache(...args),
}));

import { getNotifications, TRIGGER_EVENT_TYPES_VALUES } from '../../../../src/manager/notificationManager';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { ACCOUNT_STATUS_ACTIVE } from '../../../../src/config/conf';
import { TIMELINE_TRIGGER_ANCHOR_CHANGED, TIMELINE_TRIGGER_MILESTONE_ADDED } from '../../../../src/modules/timeline/timeline-notification';

const user = {
  id: 'timeline-user',
  internal_id: 'timeline-user',
  account_status: ACCOUNT_STATUS_ACTIVE,
  account_lock_after_date: undefined,
  groups: [],
  organizations: [],
  personal_notifiers: [],
} as unknown as AuthUser;

describe('Timeline events and the default triggers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getEntityFromCache.mockResolvedValue({ platform_notifier_auto_trigger_assignee: true });
    getEntitiesListFromCache.mockImplementation((_context: unknown, _user: unknown, type: string) => Promise.resolve(type === ENTITY_TYPE_USER ? [user] : []));
  });

  it('should keep the timeline events selectable in the triggers users create', () => {
    expect(TRIGGER_EVENT_TYPES_VALUES).toEqual(expect.arrayContaining([TIMELINE_TRIGGER_ANCHOR_CHANGED, TIMELINE_TRIGGER_MILESTONE_ADDED]));
  });

  it('should never subscribe the triggers generated for every user to the timeline events', async () => {
    const resolved = await getNotifications({} as any);
    const generated = resolved.filter(({ trigger }) => [`default-trigger-${user.id}`, `platform-notification-${user.id}`].includes(trigger.internal_id));
    expect(generated).toHaveLength(2);
    generated.forEach(({ trigger }) => {
      expect(trigger.event_types).toEqual(['create', 'update', 'delete']);
    });
  });
});

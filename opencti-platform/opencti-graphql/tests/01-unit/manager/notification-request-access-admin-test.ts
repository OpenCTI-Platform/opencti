/**
 * Request access alerting: the "Request sharing" native trigger goes to every active human validator, but the
 * platform admin, an authorized member of every request access RFI only as a fallback, is left out whatever
 * flow (legacy or request access workflow) runs the request.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthUser } from '../../../src/types/user';

const getEntitiesListFromCache = vi.fn();
const getEntityFromCache = vi.fn();

vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: (...args: any[]) => getEntitiesListFromCache(...args),
  getEntityFromCache: (...args: any[]) => getEntityFromCache(...args),
}));

// The entities workflow feature flag is on, as on a platform that may or may not have published a request access workflow
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../src/config/conf')>();
  return { ...original, isFeatureEnabled: () => true };
});

import { getNotifications } from '../../../src/manager/notificationManager';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { ACCOUNT_STATUS_ACTIVE } from '../../../src/config/conf';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

const buildUser = (over: Partial<AuthUser>): AuthUser => ({
  id: 'user-x',
  internal_id: 'user-x',
  account_status: ACCOUNT_STATUS_ACTIVE,
  groups: [],
  organizations: [],
  personal_notifiers: [],
  ...over,
} as unknown as AuthUser);

describe('getNotifications - request access native trigger', () => {
  const context = {} as any;
  const requestAccessTriggerRecipients = async (users: AuthUser[]) => {
    getEntityFromCache.mockResolvedValue({ platform_notifier_auto_trigger_assignee: true });
    getEntitiesListFromCache.mockImplementation((_ctx: any, _user: any, type: string) => Promise.resolve(type === ENTITY_TYPE_USER ? users : []));
    const notifications = await getNotifications(context);
    return notifications
      .filter(({ trigger }) => trigger.name === 'Request sharing')
      .flatMap(({ users: recipients }) => recipients.map((recipient) => recipient.id));
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not notify the admin with the feature flag on and no request access workflow published', async () => {
    const admin = buildUser({ id: OPENCTI_ADMIN_UUID, internal_id: OPENCTI_ADMIN_UUID });
    const recipients = await requestAccessTriggerRecipients([admin]);
    expect(recipients).not.toContain(OPENCTI_ADMIN_UUID);
  });

  it('does not notify the admin when it is not a member of a validator group', async () => {
    const admin = buildUser({ id: OPENCTI_ADMIN_UUID, internal_id: OPENCTI_ADMIN_UUID, groups: [{ internal_id: 'default-group' }] as any });
    const validator = buildUser({ id: 'validator', internal_id: 'validator', groups: [{ internal_id: 'approval-admin-group' }] as any });
    const recipients = await requestAccessTriggerRecipients([admin, validator]);
    expect(recipients).toEqual(['validator']);
  });

  it('keeps notifying the regular validators', async () => {
    const recipients = await requestAccessTriggerRecipients([buildUser({ id: 'u1', internal_id: 'u1' }), buildUser({ id: 'u2', internal_id: 'u2' })]);
    expect(recipients).toEqual(['u1', 'u2']);
  });
});

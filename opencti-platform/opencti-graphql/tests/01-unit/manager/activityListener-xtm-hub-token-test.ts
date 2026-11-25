import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/cache', () => ({ getEntityFromCache: vi.fn() }));
vi.mock('../../../src/database/stream/stream-handler', () => ({ storeActivityEvent: vi.fn() }));

import activityListener from '../../../src/manager/activityListener';
import { publishUserAction, type UserAction } from '../../../src/listener/UserActionListener';
import { getEntityFromCache } from '../../../src/database/cache';
import { storeActivityEvent } from '../../../src/database/stream/stream-handler';
import { logAudit } from '../../../src/config/conf';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import { completeXTMHubDataForRegistration } from '../../../src/utils/settings.helper';
import { REDACTED_INFORMATION } from '../../../src/database/utils';
import type { AuthUser } from '../../../src/types/user';

const PLATFORM_TOKEN = 'xtm-hub-platform-token-value';
const user = { id: 'user-id', name: 'admin', origin: { socket: 'query', user_id: 'user-id' } } as unknown as AuthUser;

// The action settingsEditField publishes when an admin registers the platform to XTM Hub (XtmHubTab.tsx)
const registrationAction = (): UserAction => {
  const input = completeXTMHubDataForRegistration(user, [
    { key: 'xtm_hub_token', value: [PLATFORM_TOKEN] },
    { key: 'xtm_hub_registration_status', value: ['registered'] },
  ]);
  return {
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for \`platform settings\``,
    context_data: { id: 'settings-id', entity_type: ENTITY_TYPE_SETTINGS, input },
  } as unknown as UserAction;
};

describe('Activity listener: XTM Hub registration', () => {
  beforeEach(async () => {
    vi.resetAllMocks();
    vi.mocked(getEntityFromCache).mockResolvedValue({ valid_enterprise_edition: true, activity_listeners_users: [] } as never);
    vi.spyOn(logAudit, '_log').mockImplementation(() => undefined);
    await activityListener.start();
  });

  afterEach(async () => {
    await activityListener.shutdown();
    vi.restoreAllMocks();
  });

  it('never writes the XTM Hub platform token in the activity log', async () => {
    await publishUserAction(registrationAction());
    expect(storeActivityEvent).toHaveBeenCalledTimes(1);
    const event = vi.mocked(storeActivityEvent).mock.calls[0][0];
    expect(JSON.stringify(event)).not.toContain(PLATFORM_TOKEN);
    const { input } = event.data as unknown as { input: Array<{ key: string; value: unknown }> };
    expect(input.find((i) => i.key === 'xtm_hub_token')?.value).toEqual(REDACTED_INFORMATION);
    // The other registration values stay readable
    const statusInput = input.find((i) => i.key === 'xtm_hub_registration_status');
    expect(statusInput?.value).toEqual(['registered']);
  });

  it('never writes the XTM Hub platform token in the audit log', async () => {
    await publishUserAction(registrationAction());
    expect(logAudit._log).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(vi.mocked(logAudit._log).mock.calls[0])).not.toContain(PLATFORM_TOKEN);
  });
});

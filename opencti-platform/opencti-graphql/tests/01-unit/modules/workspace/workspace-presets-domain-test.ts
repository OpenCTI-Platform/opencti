import { beforeEach, describe, expect, it, vi } from 'vitest';
import { toB64 } from '../../../../src/utils/base64';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const mocks = vi.hoisted(() => ({ storeLoadById: vi.fn() }));
vi.mock('../../../../src/database/middleware-loader', () => ({ storeLoadById: mocks.storeLoadById }));

import { resolveCurrentUserDefaultPresetId } from '../../../../src/modules/workspace/workspace-presets-domain';

const PRESET_ID = '55555555-5555-4555-8555-555555555555';
const manifest = toB64({ presets: [{ id: PRESET_ID, name: 'Energy', values: {}, config: {} }] });
const dashboard = (id: string) => ({ id, type: 'dashboard', manifest }) as never;
const user = { id: 'user-1', groups: [], organizations: [] } as unknown as AuthUser;
const context = () => ({ source: 'test' }) as unknown as AuthContext;

describe('resolveCurrentUserDefaultPresetId', () => {
  beforeEach(() => {
    mocks.storeLoadById.mockReset();
  });

  it('should read the own choice of the user from the store, not from the authenticated user', async () => {
    mocks.storeLoadById.mockResolvedValue({ id: 'user-1', default_dashboard: 'dashboard-1', default_dashboard_preset: PRESET_ID });
    expect(await resolveCurrentUserDefaultPresetId(context(), user, dashboard('dashboard-1'))).toEqual(PRESET_ID);
    expect(await resolveCurrentUserDefaultPresetId(context(), user, dashboard('dashboard-2'))).toBeNull();
  });

  it('should read the user once per request, whatever the number of dashboards', async () => {
    mocks.storeLoadById.mockResolvedValue({ id: 'user-1', default_dashboard: 'dashboard-1', default_dashboard_preset: PRESET_ID });
    const request = context();
    const results = await Promise.all(['dashboard-1', 'dashboard-2', 'dashboard-1'].map((id) => resolveCurrentUserDefaultPresetId(request, user, dashboard(id))));
    expect(results).toEqual([PRESET_ID, null, PRESET_ID]);
    expect(mocks.storeLoadById).toHaveBeenCalledTimes(1);
    await resolveCurrentUserDefaultPresetId(context(), user, dashboard('dashboard-1'));
    expect(mocks.storeLoadById).toHaveBeenCalledTimes(2);
  });

  it('should fall back to the authenticated user when the store has no record, and skip non dashboards', async () => {
    mocks.storeLoadById.mockResolvedValue(undefined);
    const cached = { ...user, groups: [{ default_dashboard: 'dashboard-1', default_dashboard_preset: PRESET_ID }] } as unknown as AuthUser;
    expect(await resolveCurrentUserDefaultPresetId(context(), cached, dashboard('dashboard-1'))).toEqual(PRESET_ID);
    expect(await resolveCurrentUserDefaultPresetId(context(), cached, { id: 'dashboard-1', type: 'investigation', manifest } as never)).toBeNull();
    expect(mocks.storeLoadById).toHaveBeenCalledTimes(1);
  });
});

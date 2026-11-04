import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../../../../src/types/user';
import { UserMergeRightsStrategy } from '../../../../src/modules/userMerge/userMerge-types';

interface SettingsState {
  activity_listeners_ids: string[];
  platform_ip_whitelist_exclusion_ids: string[];
}

const state: SettingsState = { activity_listeners_ids: [], platform_ip_whitelist_exclusion_ids: [] };
const edits: Array<{ settingsId: string; input: Array<{ key: string; value: string[] }> }> = [];

vi.mock('../../../../src/domain/settings', () => ({
  getSettings: async () => ({ id: 'settings-id', ...state }),
  settingsEditField: async (_context: unknown, _user: unknown, settingsId: string, input: Array<{ key: string; value: string[] }>) => {
    edits.push({ settingsId, input });
    return {};
  },
}));

const { userMergeSettingsHandler, userMergeSettingsList } = await import('../../../../src/modules/userMerge/userMerge-settingsHandler');
const { USER_MERGE_REGISTER } = await import('../../../../src/modules/userMerge/userMerge-register');

const handlerContext = (strategy: UserMergeRightsStrategy) => ({
  context: {} as AuthContext,
  sourceId: 'source-id',
  targetId: 'target-id',
  options: { rightsStrategy: strategy },
} as never);

const NO_PLAN = { handler: 'settings-user-references', changes: [], alerts: [] };

describe('userMerge settings handler', () => {
  beforeEach(() => {
    state.activity_listeners_ids = [];
    state.platform_ip_whitelist_exclusion_ids = [];
    edits.length = 0;
  });

  it('should only claim rows the register declares', () => {
    const rowIds = USER_MERGE_REGISTER.map((row) => row.id);
    userMergeSettingsHandler.covers.forEach((claimed) => {
      expect(rowIds).toContain(claimed);
    });
  });

  it('should report both lists whether or not they name the source', async () => {
    state.activity_listeners_ids = ['source-id'];
    const plan = await userMergeSettingsHandler.compute(handlerContext(UserMergeRightsStrategy.Strict));
    expect(plan.changes.map((change) => [change.register_row_id, change.count])).toEqual([
      ['settings.activity-listeners-ids', 1],
      ['settings.ip-whitelist-exclusion-ids', 0],
    ]);
    expect(plan.changes.every((change) => change.exact)).toBe(true);
  });

  it('should transfer the activity listener under the strict strategy', async () => {
    state.activity_listeners_ids = ['other-id', 'source-id'];
    const written = await userMergeSettingsHandler.apply(handlerContext(UserMergeRightsStrategy.Strict), NO_PLAN);
    expect(written).toEqual(1);
    expect(edits).toEqual([{ settingsId: 'settings-id', input: [{ key: 'activity_listeners_ids', value: ['other-id', 'target-id'] }] }]);
  });

  it('should drop the ip whitelist exclusion under the strict strategy', async () => {
    state.platform_ip_whitelist_exclusion_ids = ['source-id', 'other-id'];
    await userMergeSettingsHandler.apply(handlerContext(UserMergeRightsStrategy.Strict), NO_PLAN);
    expect(edits).toEqual([{ settingsId: 'settings-id', input: [{ key: 'platform_ip_whitelist_exclusion_ids', value: ['other-id'] }] }]);
  });

  it('should transfer the ip whitelist exclusion under the union strategy', async () => {
    state.platform_ip_whitelist_exclusion_ids = ['source-id'];
    await userMergeSettingsHandler.apply(handlerContext(UserMergeRightsStrategy.Union), NO_PLAN);
    expect(edits).toEqual([{ settingsId: 'settings-id', input: [{ key: 'platform_ip_whitelist_exclusion_ids', value: ['target-id'] }] }]);
  });

  it('should not write when neither list names the source', async () => {
    state.activity_listeners_ids = ['other-id'];
    const written = await userMergeSettingsHandler.apply(handlerContext(UserMergeRightsStrategy.Union), NO_PLAN);
    expect(written).toEqual(0);
    expect(edits).toEqual([]);
  });

  it('should be a no-op on replay', async () => {
    state.activity_listeners_ids = ['target-id'];
    await userMergeSettingsHandler.apply(handlerContext(UserMergeRightsStrategy.Strict), NO_PLAN);
    expect(edits).toEqual([]);
  });

  it('should not append the target twice when both accounts are already listed', () => {
    expect(userMergeSettingsList(['source-id', 'target-id'], 'source-id', 'target-id', true)).toEqual(['target-id']);
  });
});

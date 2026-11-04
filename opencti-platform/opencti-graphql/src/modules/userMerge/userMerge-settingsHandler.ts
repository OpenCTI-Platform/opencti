import { getSettings, settingsEditField } from '../../domain/settings';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { SYSTEM_USER } from '../../utils/access';
import type { UserMergeHandler, UserMergeHandlerContext, UserMergeHandlerPlan, UserMergePlannedChange } from './userMerge-handler';
import { UserMergeRightsStrategy } from './userMerge-types';

export const USER_MERGE_SETTINGS_HANDLER = 'settings-user-references';

const FIELD_ACTIVITY_LISTENERS = 'activity_listeners_ids';
const FIELD_IP_WHITELIST_EXCLUSIONS = 'platform_ip_whitelist_exclusion_ids';

interface SettingsTarget {
  registerRow: string;
  field: string;
  /** Whether the target inherits the entry, or the source merely loses it. */
  inherits: (strategy: UserMergeRightsStrategy) => boolean;
  detail: (inherited: boolean) => string;
}

/**
 * The two platform-wide lists naming individual users.
 *
 * They read alike and behave in opposite ways, because one is a constraint placed on an account
 * and the other is an exemption granted to it.
 *
 * Being listened to is not a right: `activity_listeners_ids` turns on extended traceability —
 * entity reads, file downloads, dashboard views — on the accounts it names. Dropping it under
 * STRICT would silently narrow the audit surface, so it follows the reference and not the
 * strategy. The IP allow list exclusion is the mirror image: it lets an account reach the
 * platform from outside the trusted ranges, so carrying it over under STRICT would grant the
 * target a network exemption the operator did not ask for.
 */
const SETTINGS_TARGETS: SettingsTarget[] = [
  {
    registerRow: 'settings.activity-listeners-ids',
    field: FIELD_ACTIVITY_LISTENERS,
    inherits: () => true,
    detail: () => 'transferred: extended traceability is a constraint on the account, not a right the strategy arbitrates',
  },
  {
    registerRow: 'settings.ip-whitelist-exclusion-ids',
    field: FIELD_IP_WHITELIST_EXCLUSIONS,
    inherits: (strategy) => strategy === UserMergeRightsStrategy.Union,
    detail: (inherited) => (inherited
      ? 'transferred: the union strategy carries the source exemptions over'
      : 'dropped: the strict strategy does not grant the target a network exemption it did not hold'),
  },
];

const fieldPaths = SETTINGS_TARGETS.map((target) => `${ENTITY_TYPE_SETTINGS}.${target.field}`);

/**
 * The list as it must read after the merge.
 *
 * The target only ever inherits an entry the source actually held — an absent source leaves the
 * list untouched rather than enrolling the target. Removal then guarded append, like every other
 * multiple-value rewrite: replaying the merge on an already-merged platform yields the same list
 * rather than a second entry.
 */
export const userMergeSettingsList = (
  current: string[],
  sourceId: string,
  targetId: string,
  inherits: boolean,
): string[] => {
  if (!current.includes(sourceId)) {
    return current;
  }
  const withoutSource = current.filter((id) => id !== sourceId);
  if (!inherits || withoutSource.includes(targetId)) {
    return withoutSource;
  }
  return [...withoutSource, targetId];
};

/**
 * Rewrites the two Settings lists that name users one by one.
 *
 * Written through `settingsEditField` rather than a bulk index update: the platform cache serves
 * `activity_listeners_users` from this document, and a write that bypasses the domain layer would
 * leave every node answering from a stale copy until the next refresh.
 */
export const userMergeSettingsHandler: UserMergeHandler = {
  identifier: USER_MERGE_SETTINGS_HANDLER,
  covers: SETTINGS_TARGETS.map((target) => target.registerRow),
  reads: fieldPaths,
  writes: fieldPaths,
  compute: async ({ context, sourceId, options }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const settings = await getSettings(context);
    const changes: UserMergePlannedChange[] = SETTINGS_TARGETS.map((target) => {
      const current = (settings as unknown as Record<string, string[] | undefined>)[target.field] ?? [];
      const inherited = target.inherits(options.rightsStrategy);
      return {
        register_row_id: target.registerRow,
        entity_type: ENTITY_TYPE_SETTINGS,
        count: current.includes(sourceId) ? 1 : 0,
        exact: true,
        detail: target.detail(inherited),
      };
    });
    return { handler: USER_MERGE_SETTINGS_HANDLER, changes, alerts: [] };
  },
  apply: async ({ context, sourceId, targetId, options }: UserMergeHandlerContext): Promise<number> => {
    const settings = await getSettings(context);
    const input = [];
    for (let i = 0; i < SETTINGS_TARGETS.length; i += 1) {
      const target = SETTINGS_TARGETS[i];
      const current = (settings as unknown as Record<string, string[] | undefined>)[target.field] ?? [];
      const next = userMergeSettingsList(current, sourceId, targetId, target.inherits(options.rightsStrategy));
      if (next.length !== current.length || next.some((id, index) => id !== current[index])) {
        input.push({ key: target.field, value: next });
      }
    }
    if (input.length === 0) {
      return 0;
    }
    await settingsEditField(context, SYSTEM_USER, settings.id, input);
    return input.length;
  },
};

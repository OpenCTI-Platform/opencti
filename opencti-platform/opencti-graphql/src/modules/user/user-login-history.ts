import { isFeatureEnabled, logApp, LOGIN_HISTORY_FEATURE_FLAG } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { getEntityFromCache } from '../../database/cache';
import { elRawSearch } from '../../database/engine';
import { READ_INDEX_HISTORY } from '../../database/utils';
import { isEnterpriseEditionFromSettings } from '../../enterprise-edition/ee';
import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import type { BasicStoreSettings } from '../../types/settings';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';

// Login history: a user sees their own last successful logins in their profile.
// Nothing is stored for it: the logins are read from the activity log, so the feature needs an Enterprise Edition licence.

export const LOGIN_HISTORY_SETTING = 'platform_login_history_count';
export const LOGIN_HISTORY_MAX_COUNT = 50;

export interface UserLoginEntry {
  id: string;
  timestamp: string;
  provider: string | null;
}

export const isValidLoginHistoryCount = (value: unknown): value is number => {
  return Number.isInteger(value) && (value as number) >= 0 && (value as number) <= LOGIN_HISTORY_MAX_COUNT;
};

// The only reader of the setting: 0 when the feature flag is off or the stored value is not usable.
export const readLoginHistoryCount = (settings: Pick<BasicStoreSettings, 'platform_login_history_count'> | null | undefined): number => {
  if (!isFeatureEnabled(LOGIN_HISTORY_FEATURE_FLAG)) {
    return 0;
  }
  const value = settings?.platform_login_history_count;
  if (value === undefined || value === null) {
    return 0;
  }
  if (!isValidLoginHistoryCount(value)) {
    logApp.warn('[LOGIN_HISTORY] Ignoring an invalid login history count', { value });
    return 0;
  }
  return value;
};

// Checks the values of a settings edit of the login history count. The edit values come as strings or numbers
export const checkLoginHistoryCountEdit = (values: unknown[] | null | undefined) => {
  if (!isFeatureEnabled(LOGIN_HISTORY_FEATURE_FLAG)) {
    throw FunctionalError('The login history is not available');
  }
  const [value] = values ?? [];
  const count = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if ((values ?? []).length !== 1 || !isValidLoginHistoryCount(count)) {
    throw FunctionalError(`The login history count must be an integer between 0 and ${LOGIN_HISTORY_MAX_COUNT}`, { value });
  }
};

// The last successful logins of the user, newest first. Read as the system user, as the activity log is only open
// to the security administrators, but always restricted to the logins of the given user.
export const findUserLoginHistory = async (context: AuthContext, user: AuthUser): Promise<UserLoginEntry[]> => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  const count = readLoginHistoryCount(settings);
  if (count === 0 || !isEnterpriseEditionFromSettings(settings)) {
    return [];
  }
  const result = await elRawSearch(context, SYSTEM_USER, ENTITY_TYPE_ACTIVITY, {
    index: READ_INDEX_HISTORY,
    size: count,
    track_total_hits: false,
    _source: ['internal_id', 'timestamp', 'context_data.provider'],
    body: {
      query: {
        bool: {
          filter: [
            { term: { 'entity_type.keyword': { value: ENTITY_TYPE_ACTIVITY } } },
            { term: { 'event_scope.keyword': { value: 'login' } } },
            { term: { 'event_status.keyword': { value: 'success' } } },
            { term: { 'user_id.keyword': { value: user.id } } },
          ],
        },
      },
      sort: [{ timestamp: 'desc' }],
    },
  });
  const hits = (result.hits?.hits ?? []) as { _source: { internal_id: string; timestamp: string; context_data?: { provider?: string } } }[];
  return hits.map(({ _source }) => ({
    id: _source.internal_id,
    timestamp: _source.timestamp,
    provider: _source.context_data?.provider ?? null,
  }));
};

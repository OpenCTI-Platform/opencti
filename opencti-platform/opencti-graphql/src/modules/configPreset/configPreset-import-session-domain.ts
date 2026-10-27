import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { getSettingsFromDatabase } from '../../domain/settings';
import { deleteFile } from '../../database/file-storage';
import { redisDeleteConfigPresetImportSession, redisGetConfigPresetImportSession, redisSetConfigPresetImportSession } from '../../database/redis';
import { lockResources } from '../../lock/master-lock';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetSelectionInput } from '../../generated/graphql';
import { checkConfigPresetImportAccess } from './configPreset-import-utils';
import {
  CONFIG_PRESET_IMPORT_SESSION_VERSION,
  type ConfigPresetImportSelection,
  type ConfigPresetImportSession,
  type ConfigPresetImportSessionEvent,
  type ConfigPresetImportSessionPayloads,
  getConfigPresetImportAvailableEvents,
  transitionConfigPresetImportSession,
} from './configPreset-import-session';

const SESSION_STATUSES = ['DRAFT', 'APPLYING', 'FINISHED'];

export const getConfigPresetPlatformId = async (context: AuthContext): Promise<string> => (await getSettingsFromDatabase(context))!.internal_id;

// A session of another platform (restore on the same Redis), of an unknown version or status is no session: logged, never thrown
const readSession = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetImportSession | null> => {
  const stored = (await redisGetConfigPresetImportSession(user.id)) as Partial<ConfigPresetImportSession> | null;
  if (!stored) {
    return null;
  }
  const platformId = await getConfigPresetPlatformId(context);
  if (stored.v !== CONFIG_PRESET_IMPORT_SESSION_VERSION || stored.platform_id !== platformId || !SESSION_STATUSES.includes(stored.status as string)) {
    logApp.warn('[CONFIG PRESET] Ignoring an import session that does not belong to this platform or is unreadable', { user_id: user.id });
    return null;
  }
  return stored as ConfigPresetImportSession;
};

// The read-modify-write of a session of a user runs under a small per-user lock, so that a stale tab cannot overwrite applying
const withSessionLock = async <T>(user: AuthUser, fn: () => Promise<T>): Promise<T> => {
  const lock = await lockResources([`config_preset_import_session_lock_${user.id}`]);
  try {
    return await fn();
  } finally {
    await lock.unlock();
  }
};

// Every change of the session goes through here: the transition list decides, a refused event is a FunctionalError
export const applyConfigPresetImportEvent = async <E extends ConfigPresetImportSessionEvent>(
  context: AuthContext,
  user: AuthUser,
  event: E,
  payload: ConfigPresetImportSessionPayloads[E],
): Promise<ConfigPresetImportSession | null> => {
  return withSessionLock(user, async () => {
    const next = transitionConfigPresetImportSession(await readSession(context, user), event, payload);
    if (next) {
      await redisSetConfigPresetImportSession(user.id, next);
    } else {
      await redisDeleteConfigPresetImportSession(user.id);
    }
    return next;
  });
};

export const toSessionSelections = (selections: ConfigPresetSelectionInput[]): ConfigPresetImportSelection[] => {
  return selections.map(({ type, items, excluded_items }) => ({ type, items: items ?? null, excluded_items: excluded_items ?? null }));
};

const toGraphqlSession = (session: ConfigPresetImportSession | null) => {
  return session ? { ...session, available_events: getConfigPresetImportAvailableEvents(session) } : null;
};

export const findConfigPresetImportSession = async (context: AuthContext, user: AuthUser) => {
  checkConfigPresetImportAccess(context, user);
  return toGraphqlSession(await readSession(context, user));
};

// An upload while the import runs would delete the zip being imported
export const checkConfigPresetImportNotApplying = async (context: AuthContext, user: AuthUser) => {
  if ((await readSession(context, user))?.status === 'APPLYING') {
    throw FunctionalError('An import is in progress', { event: 'UPLOAD', status: 'APPLYING' });
  }
};

export const saveConfigPresetImportSession = async (
  context: AuthContext,
  user: AuthUser,
  fileId: string,
  selections: ConfigPresetSelectionInput[],
  revision: number,
) => {
  checkConfigPresetImportAccess(context, user);
  const session = await applyConfigPresetImportEvent(context, user, 'SAVE', { file_id: fileId, selections: toSessionSelections(selections), revision });
  return toGraphqlSession(session);
};

// Start over (from draft) and Close (from finished): the session is deleted, and the pending zip with deleteFileToo
export const clearConfigPresetImportSession = async (context: AuthContext, user: AuthUser, deleteFileToo: boolean) => {
  checkConfigPresetImportAccess(context, user);
  const session = await readSession(context, user);
  const event = session?.status === 'FINISHED' ? 'CLOSE' : 'START_OVER';
  await applyConfigPresetImportEvent(context, user, event, undefined);
  if (deleteFileToo && session) {
    try {
      await deleteFile(context, user, session.file_id, { forceDelete: true });
    } catch (err) {
      logApp.warn('[CONFIG PRESET] Failed to delete the pending import file', { cause: err, file_id: session.file_id });
    }
  }
  return true;
};

import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { deleteFile } from '../../database/file-storage';
import { redisDeleteConfigPresetImportSession, redisGetConfigPresetImportSession, redisSetConfigPresetImportSession } from '../../database/redis';
import { lockResources } from '../../lock/master-lock';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetSelectionInput } from '../../generated/graphql';
import { checkConfigPresetImportAccess, getConfigPresetPlatformId } from './configPreset-import-utils';
import { isConfigPresetImportLocked } from './configPreset-import-lock';
import { readConfigPresetImportRunningRecord } from './configPreset-import-running';
import {
  CONFIG_PRESET_IMPORT_SESSION_VERSION,
  type ConfigPresetImportSelection,
  type ConfigPresetImportSession,
  type ConfigPresetImportSessionEvent,
  type ConfigPresetImportSessionPayloads,
  getConfigPresetImportAvailableEvents,
  transitionConfigPresetImportSession,
} from './configPreset-import-session';

// INTERRUPTED is never stored
const SESSION_STATUSES = ['DRAFT', 'APPLYING', 'FINISHED'];

// A session of another platform (restore on the same Redis), of an unknown version or status is no session: logged, never thrown
const readStoredSession = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetImportSession | null> => {
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

// A session stored as applying is read as interrupted unless the import still runs: the lock is held and the running record
// is absent (the window between the lock and the record) or belongs to this user and this start date. A lock check or a
// record read that cannot answer returns the stored status, never interrupted.
const deriveInterrupted = async (context: AuthContext, user: AuthUser, session: ConfigPresetImportSession): Promise<ConfigPresetImportSession> => {
  if (session.status !== 'APPLYING') {
    return session;
  }
  try {
    const isRunning = await isConfigPresetImportLocked();
    const record = isRunning ? await readConfigPresetImportRunningRecord(context) : null;
    const isOwnRun = isRunning && (!record || (record.user_id === user.id && record.started_at === session.started_at));
    return isOwnRun ? session : { ...session, status: 'INTERRUPTED' };
  } catch (err) {
    logApp.warn('[CONFIG PRESET] Cannot tell whether the import still runs, the session is read as stored', { cause: err });
    return session;
  }
};

// The session as the user sees it, with the derived status
export const readConfigPresetImportSession = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetImportSession | null> => {
  const stored = await readStoredSession(context, user);
  return stored ? deriveInterrupted(context, user, stored) : null;
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
    const next = transitionConfigPresetImportSession(await readConfigPresetImportSession(context, user), event, payload);
    if (next) {
      await redisSetConfigPresetImportSession(user.id, next);
    } else {
      await redisDeleteConfigPresetImportSession(user.id);
    }
    return next;
  });
};

// The write of a run of the engine: applied only while the stored session is applying with the start date of this run,
// otherwise skipped and logged, so that a stale run never touches a session it no longer owns
export const applyConfigPresetImportRunEvent = async <E extends ConfigPresetImportSessionEvent>(
  context: AuthContext,
  user: AuthUser,
  startedAt: string,
  event: E,
  payload: ConfigPresetImportSessionPayloads[E],
): Promise<boolean> => {
  return withSessionLock(user, async () => {
    const session = await readStoredSession(context, user);
    if (session?.status !== 'APPLYING' || session.started_at !== startedAt) {
      logApp.warn('[CONFIG PRESET] Skipping the write of an import run that no longer owns the session', { user_id: user.id, event });
      return false;
    }
    const next = transitionConfigPresetImportSession(session, event, payload);
    await redisSetConfigPresetImportSession(user.id, next!);
    return true;
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
  return toGraphqlSession(await readConfigPresetImportSession(context, user));
};

// An upload while the import runs would delete the zip being imported
export const checkConfigPresetImportNotApplying = async (context: AuthContext, user: AuthUser) => {
  const status = (await readConfigPresetImportSession(context, user))?.status;
  if (status === 'APPLYING') {
    throw FunctionalError('An import is in progress', { event: 'UPLOAD', status });
  }
  if (status === 'INTERRUPTED') {
    throw FunctionalError('The previous import was interrupted, start over first', { event: 'UPLOAD', status });
  }
};

// Back to the selection of an interrupted import: the file and the selection are kept
export const backToConfigPresetImportSelection = async (context: AuthContext, user: AuthUser) => {
  checkConfigPresetImportAccess(context, user);
  return toGraphqlSession(await applyConfigPresetImportEvent(context, user, 'BACK_TO_SELECTION', undefined));
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
  const session = await readConfigPresetImportSession(context, user);
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

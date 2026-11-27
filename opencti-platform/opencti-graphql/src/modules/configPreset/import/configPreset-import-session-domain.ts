import { logApp } from '../../../config/conf';
import { FunctionalError, UnsupportedError } from '../../../config/errors';
import { deleteFile } from '../../../database/file-storage';
import {
  redisAppendConfigPresetImportResult,
  redisDeleteConfigPresetImportResults,
  redisDeleteConfigPresetImportSession,
  redisGetConfigPresetImportSession,
  redisReadConfigPresetImportProgress,
  redisReadConfigPresetImportResults,
  redisSetConfigPresetImportSession,
} from '../../../database/redis';
import { lockResources } from '../../../lock/master-lock';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { ConfigPresetSelectionInput } from '../../../generated/graphql';
import { checkConfigPresetImportAccess, getConfigPresetPlatformId } from './configPreset-import-utils';
import { dropConfigPresetImportCache } from './configPreset-import-cache';
import { isConfigPresetImportLocked } from './configPreset-import-lock';
import { readConfigPresetImportRunningRecord } from './configPreset-import-running';
import {
  CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT,
  CONFIG_PRESET_IMPORT_RECENT_LIMIT,
  CONFIG_PRESET_IMPORT_SESSION_VERSION,
  configPresetResultBucket,
  emptyConfigPresetImportProgress,
  isConfigPresetResultProblem,
  summarizeConfigPresetImportResults,
  toConfigPresetImportTypeCounts,
  type ConfigPresetImportGraphqlSession,
  type ConfigPresetImportProgress,
  type ConfigPresetImportItemResult,
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

// The session with its derived status, without its results: what the transitions read and write back, and what a caller that
// only needs the status reads. The results of a run are not in the session but in a list of their own (see redis.ts).
const readConfigPresetImportSessionState = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetImportSession | null> => {
  const stored = await readStoredSession(context, user);
  return stored ? deriveInterrupted(context, user, stored) : null;
};

// The session as the user sees it, with the derived status, without its results (they are read apart, see readConfigPresetImportResults)
export const readConfigPresetImportSession = readConfigPresetImportSessionState;

// Every result of the run: a list of tens of thousands for a big bundle, read only for the caller that asks for it. A session stored before
// the results had a list keeps them inside it.
export const readConfigPresetImportResults = async (user: AuthUser, session: ConfigPresetImportSession): Promise<ConfigPresetImportItemResult[]> => {
  if (session.results.length > 0 || !session.started_at) {
    return session.results;
  }
  return await redisReadConfigPresetImportResults(user.id, session.started_at) as ConfigPresetImportItemResult[];
};

// What a screen shows of the run, whatever its number of items: the counts, the first problems, the last items. One read of a few keys.
// A session stored before the counters keeps its results inside it: they are summarized from there.
const readConfigPresetImportProgress = async (user: AuthUser, session: ConfigPresetImportSession): Promise<ConfigPresetImportProgress> => {
  if (session.results.length > 0) {
    return summarizeConfigPresetImportResults(session.results);
  }
  if (!session.started_at) {
    return emptyConfigPresetImportProgress();
  }
  const { processed, counters, problems, recent } = await redisReadConfigPresetImportProgress(
    user.id,
    session.started_at,
    CONFIG_PRESET_IMPORT_PROBLEMS_LIMIT,
    CONFIG_PRESET_IMPORT_RECENT_LIMIT,
  );
  return {
    processed,
    type_counts: toConfigPresetImportTypeCounts(counters),
    problems: problems as ConfigPresetImportItemResult[],
    recent: recent as ConfigPresetImportItemResult[],
  };
};

// A run of the session that is gone (the session was deleted, or left the run it had) has no use for its results
const dropConfigPresetImportResults = async (user: AuthUser, previous: ConfigPresetImportSession | null, next: ConfigPresetImportSession | null) => {
  if (previous?.started_at && next?.started_at !== previous.started_at) {
    try {
      await redisDeleteConfigPresetImportResults(user.id, previous.started_at);
    } catch (err) {
      // The list expires with the session TTL anyway
      logApp.warn('[CONFIG PRESET] The results of the previous import could not be deleted', { cause: err });
    }
  }
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
    const previous = await readConfigPresetImportSessionState(context, user);
    const next = transitionConfigPresetImportSession(previous, event, payload);
    if (next) {
      await redisSetConfigPresetImportSession(user.id, next);
    } else {
      await redisDeleteConfigPresetImportSession(user.id);
    }
    await dropConfigPresetImportResults(user, previous, next);
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
  // The result of an item is appended to the list of its run: the session is not read, copied and written back for each item
  // (its cost would grow with the number of results), and it is not changed, so no lock is needed. The run still has to own it.
  if (event === 'ITEM_PROCESSED') {
    const stored = await redisGetConfigPresetImportSession(user.id) as Partial<ConfigPresetImportSession> | null;
    if (stored?.status !== 'APPLYING' || stored.started_at !== startedAt) {
      logApp.warn('[CONFIG PRESET] Skipping the write of an import run that no longer owns the session', { user_id: user.id, event });
      return false;
    }
    const { result } = payload as ConfigPresetImportSessionPayloads['ITEM_PROCESSED'];
    await redisAppendConfigPresetImportResult(user.id, startedAt, result, {
      counter: `${result.type}|${configPresetResultBucket(result)}`,
      isProblem: isConfigPresetResultProblem(result),
    });
    return true;
  }
  return withSessionLock(user, async () => {
    const session = await readStoredSession(context, user);
    if (session?.status !== 'APPLYING' || session.started_at !== startedAt) {
      logApp.warn('[CONFIG PRESET] Skipping the write of an import run that no longer owns the session', { user_id: user.id, event });
      return false;
    }
    const next = transitionConfigPresetImportSession(session, event, payload);
    await redisSetConfigPresetImportSession(user.id, next!);
    await dropConfigPresetImportResults(user, session, next);
    return true;
  });
};

export const toSessionSelections = (selections: ConfigPresetSelectionInput[]): ConfigPresetImportSelection[] => {
  return selections.map(({ type, items, excluded_items, item_modes }) => ({
    type,
    items: items ?? null,
    excluded_items: excluded_items ?? null,
    item_modes: item_modes && item_modes.length > 0 ? item_modes.map(({ key, mode }) => ({ key, mode })) : null,
  }));
};

const toGraphqlSession = (session: ConfigPresetImportSession, progress: ConfigPresetImportProgress = emptyConfigPresetImportProgress()): ConfigPresetImportGraphqlSession => {
  return { ...session, ...progress, available_events: getConfigPresetImportAvailableEvents(session) };
};

// The events that keep a session (save, back to the selection) never end it: the schema returns a session, not null
const toKeptGraphqlSession = (session: ConfigPresetImportSession | null, event: ConfigPresetImportSessionEvent): ConfigPresetImportGraphqlSession => {
  if (!session) {
    throw UnsupportedError('The import session was deleted by an event that keeps it', { event });
  }
  return toGraphqlSession(session);
};

export const findConfigPresetImportSession = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetImportGraphqlSession | null> => {
  checkConfigPresetImportAccess(context, user);
  const session = await readConfigPresetImportSession(context, user);
  return session ? toGraphqlSession(session, await readConfigPresetImportProgress(user, session)) : null;
};

// An upload while the import runs would delete the zip being imported
export const checkConfigPresetImportNotApplying = async (context: AuthContext, user: AuthUser) => {
  const status = (await readConfigPresetImportSessionState(context, user))?.status;
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
  return toKeptGraphqlSession(await applyConfigPresetImportEvent(context, user, 'BACK_TO_SELECTION', undefined), 'BACK_TO_SELECTION');
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
  return toKeptGraphqlSession(session, 'SAVE');
};

// Start over (from draft) and Close (from finished): the session is deleted, and the pending zip with deleteFileToo
export const clearConfigPresetImportSession = async (context: AuthContext, user: AuthUser, deleteFileToo: boolean) => {
  checkConfigPresetImportAccess(context, user);
  const session = await readConfigPresetImportSessionState(context, user);
  const event = session?.status === 'FINISHED' ? 'CLOSE' : 'START_OVER';
  await applyConfigPresetImportEvent(context, user, event, undefined);
  // The zip is replaced or deleted: what was kept of it is of no use any more
  dropConfigPresetImportCache(user.id);
  if (deleteFileToo && session) {
    try {
      await deleteFile(context, user, session.file_id, { forceDelete: true });
    } catch (err) {
      logApp.warn('[CONFIG PRESET] Failed to delete the pending import file', { cause: err, file_id: session.file_id });
    }
  }
  return true;
};

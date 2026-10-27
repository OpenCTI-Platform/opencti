import { logApp } from '../../config/conf';
import {
  redisDeleteConfigPresetImportRunning,
  redisGetConfigPresetImportLastFinished,
  redisGetConfigPresetImportRunning,
  redisSetConfigPresetImportLastFinished,
  redisSetConfigPresetImportRunning,
  redisUpdateConfigPresetImportRunning,
} from '../../database/redis';
import type { AuthContext, AuthUser } from '../../types/user';
import { resolveUserByIdFromCache } from '../user/user-domain';
import { isConfigPresetImportLocked } from './configPreset-import-lock';
import { getConfigPresetPlatformId } from './configPreset-import-utils';

const RUNNING_RECORD_VERSION = 1;

// The running record of a real import, in Redis
export interface ConfigPresetImportRunningRecord {
  v: typeof RUNNING_RECORD_VERSION;
  // internal_id of the Settings
  platform_id: string;
  user_id: string;
  // The same string as the started_at of the session
  started_at: string;
  total: number;
  processed: number;
}

// A record of another platform, of an unknown version or unreadable is no record
export const readConfigPresetImportRunningRecord = async (context: AuthContext): Promise<ConfigPresetImportRunningRecord | null> => {
  const record = (await redisGetConfigPresetImportRunning()) as Partial<ConfigPresetImportRunningRecord> | null;
  if (!record || record.v !== RUNNING_RECORD_VERSION || record.platform_id !== await getConfigPresetPlatformId(context)) {
    return null;
  }
  return record as ConfigPresetImportRunningRecord;
};

export const startConfigPresetImportRunning = async (context: AuthContext, user: AuthUser, startedAt: string, total: number) => {
  const record: ConfigPresetImportRunningRecord = {
    v: RUNNING_RECORD_VERSION,
    platform_id: await getConfigPresetPlatformId(context),
    user_id: user.id,
    started_at: startedAt,
    total,
    processed: 0,
  };
  await redisSetConfigPresetImportRunning(record);
};

// The writes of a run on its record never fail the import: a failure is logged
export const updateConfigPresetImportRunning = async (user: AuthUser, startedAt: string, processed: number) => {
  try {
    await redisUpdateConfigPresetImportRunning(user.id, startedAt, processed);
  } catch (err) {
    logApp.warn('[CONFIG PRESET] The running record of the import could not be updated', { cause: err });
  }
};

// At the end of an import: the record is deleted and, for a completed or stopped import, last_finished_at is written.
// Both apply only while the record still holds this run: a stale run leaves the import that took over untouched.
export const endConfigPresetImportRunning = async (user: AuthUser, startedAt: string, hasFinished: boolean) => {
  try {
    if (await redisDeleteConfigPresetImportRunning(user.id, startedAt) && hasFinished) {
      await redisSetConfigPresetImportLastFinished(new Date().toISOString());
    }
  } catch (err) {
    logApp.warn('[CONFIG PRESET] The running record of the import could not be deleted', { cause: err });
  }
};

// Running means the lock is held and the record exists. A failing lock check or read answers "not running", and is logged.
export const findConfigPresetImportRunning = async (context: AuthContext, user: AuthUser) => {
  let lastFinishedAt: string | null = null;
  try {
    lastFinishedAt = await redisGetConfigPresetImportLastFinished();
  } catch (err) {
    logApp.warn('[CONFIG PRESET] The end date of the last import could not be read', { cause: err });
  }
  try {
    const record = (await isConfigPresetImportLocked()) ? await readConfigPresetImportRunningRecord(context) : null;
    if (!record) {
      return { running: null, last_finished_at: lastFinishedAt };
    }
    // Only the name is exposed, never the id of the user: it is not found for a user that no longer exists
    const importer = await resolveUserByIdFromCache(context, record.user_id);
    return {
      running: {
        name: importer?.name ?? null,
        is_mine: record.user_id === user.id,
        started_at: record.started_at,
        processed: record.processed,
        total: record.total,
      },
      last_finished_at: lastFinishedAt,
    };
  } catch (err) {
    logApp.warn('[CONFIG PRESET] The running import could not be read', { cause: err });
    return { running: null, last_finished_at: lastFinishedAt };
  }
};

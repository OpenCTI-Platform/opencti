import { logApp } from '../../config/conf';
import { FunctionalError, TYPE_LOCK_ERROR } from '../../config/errors';
import { isResourceLocked } from '../../database/redis';
import { lockResources } from '../../lock/master-lock';

// One real import at a time on the platform, whatever it contains and whoever starts it. Platform-wide: never a draftId.
export const CONFIG_PRESET_IMPORT_LOCK_KEY = 'config_preset_import';
export const CONFIG_PRESET_REASON_IMPORT_RUNNING = 'import_running';

type ConfigPresetImportLock = Awaited<ReturnType<typeof lockResources>>;

// Runs the import under the lock, released in the finally whatever the result. The lock is taken without waiting: a second
// import is refused at once. It is extended automatically; when the extension fails its signal is aborted.
export const withConfigPresetImportLock = async <T>(fn: (lock: ConfigPresetImportLock) => Promise<T>): Promise<T> => {
  let lock: ConfigPresetImportLock;
  try {
    lock = await lockResources([CONFIG_PRESET_IMPORT_LOCK_KEY], { retryCount: 0 });
  } catch (err) {
    // The name is compared, never instanceof: in child-lock mode the error comes back as a plain object
    if ((err as { name?: string })?.name === TYPE_LOCK_ERROR) {
      throw FunctionalError('An import is already running', { reason: CONFIG_PRESET_REASON_IMPORT_RUNNING });
    }
    throw err;
  }
  try {
    return await fn(lock);
  } finally {
    // One unlock only: a second one never returns in child-lock mode
    await lock.unlock().catch((err: unknown) => logApp.warn('[CONFIG PRESET] The import lock could not be released', { cause: err }));
  }
};

// Whether an import is running, read from the lock key without taking the lock
export const isConfigPresetImportLocked = () => isResourceLocked(CONFIG_PRESET_IMPORT_LOCK_KEY);

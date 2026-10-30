import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/lock/master-lock', () => ({ lockResources: vi.fn() }));
vi.mock('../../../../../src/database/redis', () => ({ isResourceLocked: vi.fn() }));

import { lockResources } from '../../../../../src/lock/master-lock';
import { isResourceLocked } from '../../../../../src/database/redis';
import { TYPE_LOCK_ERROR } from '../../../../../src/config/errors';
import type { AuthContext } from '../../../../../src/types/user';
import { CONFIG_PRESET_IMPORT_LOCK_KEY, isConfigPresetImportLocked, withConfigPresetImportLock } from '../../../../../src/modules/configPreset/import/configPreset-import-lock';

const context = { source: 'test' } as AuthContext;
const handle = () => ({ signal: new AbortController().signal, unlock: vi.fn().mockResolvedValue(undefined) });

describe('Config preset import lock', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('takes a platform-wide lock without waiting', async () => {
    vi.mocked(lockResources).mockResolvedValue(handle() as never);
    await withConfigPresetImportLock(context, async () => 'done');
    expect(lockResources).toHaveBeenCalledWith(['config_preset_import'], { retryCount: 0 });
    expect(CONFIG_PRESET_IMPORT_LOCK_KEY).toEqual('config_preset_import');
  });

  it('refuses at once with the reason when the lock is held, comparing the name of the error', async () => {
    vi.mocked(lockResources).mockRejectedValue({ name: TYPE_LOCK_ERROR });
    const error = await withConfigPresetImportLock(context, async () => 'never').catch((err: { message: string; extensions: { data: Record<string, unknown> } }) => err) as { message: string; extensions: { data: Record<string, unknown> } };
    expect(error.message).toEqual('An import is already running');
    expect(error.extensions.data.reason).toEqual('import_running');
  });

  it('adds the name of the administrator who started the running import to the refusal when it is known', async () => {
    vi.mocked(lockResources).mockRejectedValue({ name: TYPE_LOCK_ERROR });
    const named = await withConfigPresetImportLock(context, async () => 'never', async () => 'Jane').catch((err) => err);
    expect(named.extensions.data).toMatchObject({ reason: 'import_running', started_by: 'Jane' });
    const unnamed = await withConfigPresetImportLock(context, async () => 'never', async () => undefined).catch((err) => err);
    expect(unnamed.extensions.data).not.toHaveProperty('started_by');
    const failing = await withConfigPresetImportLock(context, async () => 'never', async () => {
      throw new Error('redis down');
    }).catch((err) => err);
    expect(failing.extensions.data).toMatchObject({ reason: 'import_running' });
    expect(failing.extensions.data).not.toHaveProperty('started_by');
  });

  it('rethrows any other error of the lock', async () => {
    vi.mocked(lockResources).mockRejectedValue(new Error('redis down'));
    await expect(withConfigPresetImportLock(context, async () => 'never')).rejects.toThrow('redis down');
  });

  it('releases the lock exactly once, on success and on error, and never fails on a failed release', async () => {
    const ok = handle();
    vi.mocked(lockResources).mockResolvedValueOnce(ok as never);
    await withConfigPresetImportLock(context, async () => 'done');
    expect(ok.unlock).toHaveBeenCalledTimes(1);
    const failing = handle();
    vi.mocked(lockResources).mockResolvedValueOnce(failing as never);
    await expect(withConfigPresetImportLock(context, async () => {
      throw new Error('import failed');
    })).rejects.toThrow('import failed');
    expect(failing.unlock).toHaveBeenCalledTimes(1);
    const brokenUnlock = { ...handle(), unlock: vi.fn().mockRejectedValue(new Error('unlock failed')) };
    vi.mocked(lockResources).mockResolvedValueOnce(brokenUnlock as never);
    await expect(withConfigPresetImportLock(context, async () => 'result')).resolves.toEqual('result');
  });

  it('tells whether an import is running from the lock key, without taking the lock', async () => {
    vi.mocked(isResourceLocked).mockResolvedValue(true);
    expect(await isConfigPresetImportLocked()).toBe(true);
    expect(isResourceLocked).toHaveBeenCalledWith('config_preset_import');
    expect(lockResources).not.toHaveBeenCalled();
  });
});

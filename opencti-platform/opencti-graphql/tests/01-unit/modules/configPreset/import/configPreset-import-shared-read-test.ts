import { afterEach, describe, expect, it, vi } from 'vitest';
import { Readable } from 'node:stream';

vi.mock('../../../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/database/file-storage')>()),
  loadFile: vi.fn(),
}));
vi.mock('../../../../../src/database/raw-file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/database/raw-file-storage')>()),
  downloadFile: vi.fn(),
}));

import { loadFile } from '../../../../../src/database/file-storage';
import { downloadFile } from '../../../../../src/database/raw-file-storage';
import { ClientAbortError } from '../../../../../src/config/errors';
import { clearConfigPresetImportCache } from '../../../../../src/modules/configPreset/import/configPreset-import-cache';
import { readConfigPresetImportBundle } from '../../../../../src/modules/configPreset/import/configPreset-import-domain';
import { CONFIG_PRESET_IMPORT_PATH } from '../../../../../src/modules/internal/document/document-types';
import { BYPASS } from '../../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { buildZip, validBundleFiles } from '../../../../utils/configPresetBundle';

const user = { id: 'user-id', capabilities: [{ name: BYPASS }] } as AuthUser;
const FILE_ID = `${CONFIG_PRESET_IMPORT_PATH}/user-id/bundle.zip`;
const tick = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});

afterEach(() => {
  clearConfigPresetImportCache();
  vi.resetAllMocks();
});

describe('Config preset import: the zip read that the requests share', () => {
  it('does not fail the request that joined the read of a request that was cancelled', async () => {
    const zip = await buildZip(validBundleFiles());
    // Like the storage: a read of a cancelled request fails
    vi.mocked(loadFile).mockImplementation((async (context: AuthContext) => {
      await tick(20);
      if (context.requestAbortSignal?.aborted) {
        throw ClientAbortError('The request was cancelled');
      }
      return { internal_id: FILE_ID, metaData: { creator_id: user.id } };
    }) as never);
    vi.mocked(downloadFile).mockImplementation((async () => Readable.from([zip])) as never);

    // The dialog asks for the preview, and cancels it at once (as a dialog that closes, or a component that renders twice in development)
    const cancelled = new AbortController();
    const first = readConfigPresetImportBundle({ source: 'test', requestAbortSignal: cancelled.signal } as AuthContext, user, FILE_ID);
    first.catch(() => undefined);
    cancelled.abort();
    // The next request joins the read that is running
    const second = await readConfigPresetImportBundle({ source: 'test', requestAbortSignal: new AbortController().signal } as AuthContext, user, FILE_ID);
    expect(second.items.length).toBeGreaterThan(0);
    expect(loadFile).toHaveBeenCalledTimes(1);
  });
});

import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/database/file-storage', () => ({
  copyFile: vi.fn(),
  deleteFile: vi.fn(),
  loadFile: vi.fn(),
  uploadToStorage: vi.fn(),
}));

import { copyFile, deleteFile, loadFile, uploadToStorage } from '../../../../../src/database/file-storage';
import { writeConfigPresetImportReport } from '../../../../../src/modules/configPreset/import/configPreset-import-report';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const pending = { id: 'config_preset/import/uuid/import-report.json', name: 'import-report.json' };
const REPORT_ID = 'config_preset/history/uuid/import-report.json';
const report = {
  user_id: 'user-id',
  started_at: '2026-10-27T10:00:00.000Z',
  ended_at: '2026-10-27T10:00:01.000Z',
  bundle: { openCTI_version: '1.0.0', generated_at: 'x', bundle_name: null },
  items: [],
  outcome: 'completed' as const,
};

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(loadFile).mockResolvedValue(pending as never);
  vi.mocked(uploadToStorage).mockResolvedValue({ upload: { id: REPORT_ID, name: 'import-report.json' } } as never);
  vi.mocked(copyFile).mockResolvedValue({} as never);
  vi.mocked(deleteFile).mockResolvedValue(undefined as never);
});

describe('Config preset import report', () => {
  it('copies the zip next to the report under a fixed name, whatever the name of the upload', async () => {
    await writeConfigPresetImportReport(context, user, pending.id, report);
    const { targetId, sourceDocument } = vi.mocked(copyFile).mock.calls[0][1];
    expect(targetId).toMatch(/^config_preset\/history\/[0-9a-f-]{36}\/bundle\.zip$/);
    expect(sourceDocument.name).toEqual('bundle.zip');
    // The name of the upload is kept in the report
    const content = JSON.parse(await new Promise<string>((resolve) => {
      const chunks: Buffer[] = [];
      const stream = vi.mocked(uploadToStorage).mock.calls[0][3].createReadStream();
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    }));
    expect(content.source_file_name).toEqual('import-report.json');
  });

  it('returns the report id when the pending zip cannot be deleted afterwards', async () => {
    vi.mocked(deleteFile).mockRejectedValue(new Error('storage unavailable'));
    expect(await writeConfigPresetImportReport(context, user, pending.id, report)).toMatchObject({ reportId: REPORT_ID });
  });

  it('keeps the pending zip of a stopped import, and returns no report id when the report cannot be stored', async () => {
    await writeConfigPresetImportReport(context, user, pending.id, { ...report, outcome: 'stopped' });
    expect(deleteFile).not.toHaveBeenCalled();
    vi.mocked(uploadToStorage).mockRejectedValue(new Error('storage unavailable'));
    expect(await writeConfigPresetImportReport(context, user, pending.id, report)).toMatchObject({ reportId: null });
  });
});

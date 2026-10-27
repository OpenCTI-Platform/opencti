import crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { logApp } from '../../config/conf';
import { copyFile, deleteFile, loadFile, uploadToStorage } from '../../database/file-storage';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntityDocument } from '../internal/document/document-types';
import { CONFIG_PRESET_HISTORY_PATH } from '../internal/document/document-types';
import type { ConfigPresetBundleMetadata } from './configPreset-import-types';
import type { ConfigPresetImportItemResult } from './configPreset-import-session';

export const CONFIG_PRESET_IMPORT_REPORT_FILE = 'import-report.json';

export interface ConfigPresetImportReportInput {
  user_id: string;
  started_at: string;
  ended_at: string;
  source_file_name: string;
  bundle: ConfigPresetBundleMetadata;
  items: (ConfigPresetImportItemResult & { label: string })[];
  outcome: 'completed' | 'stopped';
}

// The report of a real import under config_preset/history/<uuid>/ with the uploaded zip copied next to it (entity_id '' so
// that a BYPASS user can read it), then the pending zip is deleted. Any failure here is a warning: the items are applied.
export const writeConfigPresetImportReport = async (
  context: AuthContext,
  user: AuthUser,
  pendingFileId: string,
  report: Omit<ConfigPresetImportReportInput, 'source_file_name'>,
): Promise<{ reportId: string | null; folder: string; fileName: string }> => {
  const folder = `${CONFIG_PRESET_HISTORY_PATH}/${crypto.randomUUID()}`;
  try {
    const pending = await loadFile(context, user, pendingFileId, { dontThrow: true });
    const content = JSON.stringify({ report_version: 1, ...report, source_file_name: pending?.name ?? null }, null, 2);
    const { upload } = await uploadToStorage(
      context,
      user,
      folder,
      { createReadStream: () => Readable.from(Buffer.from(content, 'utf8')), filename: CONFIG_PRESET_IMPORT_REPORT_FILE },
      { noTriggerImport: true, meta: { description: 'Configuration preset import report' } },
    );
    if (pending) {
      // copyFile logs at error level and returns null on a failure
      const copy = await copyFile(context, {
        sourceId: pending.id,
        targetId: `${folder}/${pending.name}`,
        sourceDocument: pending as unknown as BasicStoreEntityDocument,
        targetEntityId: '',
      });
      if (copy) {
        // A stopped import keeps the pending zip
        if (report.outcome === 'completed') {
          await deleteFile(context, user, pending.id, { forceDelete: true });
        }
      } else {
        logApp.warn('[CONFIG PRESET] The uploaded zip could not be copied next to the import report', { file_id: pending.id });
      }
    }
    return { reportId: upload.id, folder, fileName: upload.name };
  } catch (err) {
    logApp.warn('[CONFIG PRESET] The import report could not be written', { cause: err });
    return { reportId: null, folder, fileName: CONFIG_PRESET_IMPORT_REPORT_FILE };
  }
};

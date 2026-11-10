import { downloadFile } from '../../database/raw-file-storage';
import { FunctionalError } from '../../config/errors';
import { exclusionListStorageKey, MAX_FILE_SIZE } from './exclusionList-domain';
import type { BasicStoreEntityExclusionList } from './exclusionList-types';

// The file of the values of an exclusion list as the platform stores it, byte for byte.
// null when the storage has none, or when the list points at another file than its own: `file_id` is set when the list is created and cannot be
// updated, but what it holds is read by a user who may not read that file (the export), so nothing else than the list's own key is read.
// A storage error is not a missing file: it is thrown. The read is bounded by the size an exclusion list file can have.
export const readExclusionListFile = async (list: Pick<BasicStoreEntityExclusionList, 'internal_id' | 'file_id'>): Promise<Buffer | null> => {
  if (list.file_id !== exclusionListStorageKey(list.internal_id)) {
    return null;
  }
  const stream = await downloadFile(list.file_id);
  if (!stream) {
    return null;
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > MAX_FILE_SIZE) {
      stream.destroy();
      throw FunctionalError('Exclusion list file too large', { maxFileSize: MAX_FILE_SIZE, id: list.internal_id });
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
};
